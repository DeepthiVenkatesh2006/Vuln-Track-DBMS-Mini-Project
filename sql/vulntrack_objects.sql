-- =========================================================
-- VulnTrack: views, functions, stored procedures, triggers
-- Run AFTER ddl + dml (so the sample inserts don't flood the audit log).
-- Works in the mysql / mariadb command-line client (uses DELIMITER).
-- =========================================================
USE vulntrack;

-- ---------------------------------------------------------
-- FUNCTIONS
-- ---------------------------------------------------------
DROP FUNCTION IF EXISTS fn_sla_days;
DROP FUNCTION IF EXISTS fn_asset_risk;

DELIMITER //

-- Remediation deadline (days) per severity -- the "SLA" used in the dashboard and queries.
CREATE FUNCTION fn_sla_days(p_severity VARCHAR(10)) RETURNS INT
DETERMINISTIC
BEGIN
    RETURN CASE p_severity
             WHEN 'Critical' THEN 7
             WHEN 'High'     THEN 30
             WHEN 'Medium'   THEN 60
             ELSE 90
           END;
END//

-- Risk score of one asset = sum of CVSS scores of its findings whose LATEST scan is still Open.
CREATE FUNCTION fn_asset_risk(p_asset_id INT) RETURNS DECIMAL(6,1)
READS SQL DATA
BEGIN
    DECLARE total DECIMAL(6,1);
    SELECT COALESCE(SUM(v.cvss_score), 0) INTO total
    FROM SCAN_RESULTS sr
    JOIN VULNERABILITY v ON v.vuln_id = sr.vuln_id
    WHERE sr.asset_id = p_asset_id
      AND sr.detection_status = 'Open'
      AND sr.scan_date = (SELECT MAX(s2.scan_date) FROM SCAN_RESULTS s2
                          WHERE s2.asset_id = sr.asset_id AND s2.vuln_id = sr.vuln_id);
    RETURN total;
END//

DELIMITER ;

-- ---------------------------------------------------------
-- VIEWS
-- ---------------------------------------------------------
-- Latest scan row for every (asset, vulnerability) pair = the CURRENT state of that finding.
CREATE OR REPLACE VIEW v_latest_scan AS
SELECT sr.*
FROM SCAN_RESULTS sr
JOIN (SELECT asset_id, vuln_id, MAX(scan_date) AS last_scan
      FROM SCAN_RESULTS GROUP BY asset_id, vuln_id) m
  ON m.asset_id = sr.asset_id AND m.vuln_id = sr.vuln_id AND m.last_scan = sr.scan_date;

-- Every finding that is still Open, with its patch state and SLA position.
-- days_exposed counts from the FIRST time the finding was detected (not from the last scan).
CREATE OR REPLACE VIEW v_open_exposure AS
SELECT a.asset_id, a.name AS asset_name, a.owner_dept,
       v.vuln_id, v.cve_id, v.severity, v.cvss_score,
       MIN(f.scan_date)                                   AS first_detected,
       ls.scan_date                                       AS last_scanned,
       DATEDIFF(CURDATE(), MIN(f.scan_date))              AS days_exposed,
       fn_sla_days(v.severity)                            AS sla_days,
       DATEDIFF(CURDATE(), MIN(f.scan_date)) > fn_sla_days(v.severity) AS sla_breached,
       CASE WHEN COUNT(DISTINCT p.patch_id) = 0          THEN 'No patch available'
            WHEN SUM(ps.patch_status = 'Applied') > 0    THEN 'Applied'
            WHEN SUM(ps.patch_status = 'Failed')  > 0    THEN 'Failed'
            WHEN SUM(ps.patch_status = 'Pending') > 0    THEN 'Pending'
            ELSE 'Not started' END                        AS patch_state
FROM v_latest_scan ls
JOIN ASSET a          ON a.asset_id = ls.asset_id
JOIN VULNERABILITY v  ON v.vuln_id  = ls.vuln_id
JOIN SCAN_RESULTS f   ON f.asset_id = ls.asset_id AND f.vuln_id = ls.vuln_id
LEFT JOIN PATCH p     ON p.vuln_id  = v.vuln_id
LEFT JOIN PATCH_STATUS ps ON ps.patch_id = p.patch_id AND ps.asset_id = a.asset_id
WHERE ls.detection_status = 'Open'
GROUP BY a.asset_id, a.name, a.owner_dept, v.vuln_id, v.cve_id, v.severity, v.cvss_score, ls.scan_date;

-- Per-asset risk summary (assets with no open findings show 0).
CREATE OR REPLACE VIEW v_asset_risk AS
SELECT a.asset_id, a.name AS asset_name, a.type, a.owner_dept,
       COUNT(e.vuln_id)                       AS open_findings,
       COALESCE(SUM(e.severity = 'Critical'), 0) AS critical_open,
       COALESCE(SUM(e.sla_breached), 0)       AS sla_breaches,
       fn_asset_risk(a.asset_id)              AS risk_score
FROM ASSET a
LEFT JOIN v_open_exposure e ON e.asset_id = a.asset_id
GROUP BY a.asset_id, a.name, a.type, a.owner_dept;

-- ---------------------------------------------------------
-- STORED PROCEDURES
-- ---------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_register_scan;
DROP PROCEDURE IF EXISTS sp_set_patch_status;
DROP PROCEDURE IF EXISTS sp_asset_report;

DELIMITER //

-- Record a scan result by CVE id. Re-recording the same asset/CVE/date updates it.
CREATE PROCEDURE sp_register_scan(IN p_asset_id INT, IN p_cve_id VARCHAR(20),
                                  IN p_scanner VARCHAR(100), IN p_scan_date DATE,
                                  IN p_status VARCHAR(20))
BEGIN
    DECLARE v_id INT;
    SELECT vuln_id INTO v_id FROM VULNERABILITY WHERE cve_id = p_cve_id;
    IF v_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Unknown CVE id - add it to VULNERABILITY first';
    END IF;
    INSERT INTO SCAN_RESULTS (asset_id, vuln_id, scan_date, scanner_used, detection_status)
    VALUES (p_asset_id, v_id, COALESCE(p_scan_date, CURDATE()), p_scanner, p_status)
    ON DUPLICATE KEY UPDATE scanner_used = VALUES(scanner_used),
                            detection_status = VALUES(detection_status);
END//

-- Create or update the patch state of one asset/patch pair (the audit triggers log the change).
CREATE PROCEDURE sp_set_patch_status(IN p_asset_id INT, IN p_patch_id INT,
                                     IN p_status VARCHAR(20), IN p_date DATE)
BEGIN
    INSERT INTO PATCH_STATUS (asset_id, patch_id, applied_date, patch_status)
    VALUES (p_asset_id, p_patch_id, p_date, p_status)
    ON DUPLICATE KEY UPDATE patch_status = VALUES(patch_status),
                            applied_date = VALUES(applied_date);
END//

-- One-asset report: header row first, then its findings.
CREATE PROCEDURE sp_asset_report(IN p_asset_id INT)
BEGIN
    SELECT e.cve_id, e.severity, e.cvss_score, e.first_detected, e.days_exposed,
           e.sla_days, IF(e.sla_breached, 'BREACHED', 'within SLA') AS sla, e.patch_state
    FROM v_open_exposure e
    WHERE e.asset_id = p_asset_id
    ORDER BY e.cvss_score DESC;
END//

DELIMITER ;

-- ---------------------------------------------------------
-- TRIGGERS  (all on PATCH_STATUS / SCAN_RESULTS)
-- ---------------------------------------------------------
DROP TRIGGER IF EXISTS trg_ps_bi;
DROP TRIGGER IF EXISTS trg_ps_bu;
DROP TRIGGER IF EXISTS trg_ps_ai;
DROP TRIGGER IF EXISTS trg_patch_status_update;   -- original single trigger, replaced by trg_ps_au
DROP TRIGGER IF EXISTS trg_ps_au;
DROP TRIGGER IF EXISTS trg_scan_bi;

DELIMITER //

-- Integrity: a patch can only be tracked on an asset that was actually scanned for the
-- vulnerability that patch fixes. Also defaults applied_date for 'Applied' rows.
CREATE TRIGGER trg_ps_bi BEFORE INSERT ON PATCH_STATUS
FOR EACH ROW
BEGIN
    IF NOT EXISTS (SELECT 1 FROM PATCH p
                   JOIN SCAN_RESULTS sr ON sr.vuln_id = p.vuln_id
                   WHERE p.patch_id = NEW.patch_id AND sr.asset_id = NEW.asset_id) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'This asset was never scanned for the vulnerability this patch fixes';
    END IF;
    IF NEW.patch_status = 'Applied' AND NEW.applied_date IS NULL THEN
        SET NEW.applied_date = CURDATE();
    END IF;
END//

-- Keep applied_date consistent with the status.
CREATE TRIGGER trg_ps_bu BEFORE UPDATE ON PATCH_STATUS
FOR EACH ROW
BEGIN
    IF NEW.patch_status = 'Applied' AND NEW.applied_date IS NULL THEN
        SET NEW.applied_date = CURDATE();
    ELSEIF NEW.patch_status <> 'Applied' THEN
        SET NEW.applied_date = NULL;
    END IF;
END//

-- Audit log: original trigger (UPDATE) ...
CREATE TRIGGER trg_ps_au AFTER UPDATE ON PATCH_STATUS
FOR EACH ROW
BEGIN
    IF OLD.patch_status <> NEW.patch_status THEN
        INSERT INTO PATCH_STATUS_LOG (asset_id, patch_id, old_status, new_status)
        VALUES (NEW.asset_id, NEW.patch_id, OLD.patch_status, NEW.patch_status);
    END IF;
END//

-- ... plus the missing INSERT side (old_status is NULL for a brand-new row).
CREATE TRIGGER trg_ps_ai AFTER INSERT ON PATCH_STATUS
FOR EACH ROW
BEGIN
    INSERT INTO PATCH_STATUS_LOG (asset_id, patch_id, old_status, new_status)
    VALUES (NEW.asset_id, NEW.patch_id, NULL, NEW.patch_status);
END//

-- A scan cannot be dated in the future.
CREATE TRIGGER trg_scan_bi BEFORE INSERT ON SCAN_RESULTS
FOR EACH ROW
BEGIN
    IF NEW.scan_date > CURDATE() THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'scan_date cannot be in the future';
    END IF;
END//

DELIMITER ;
