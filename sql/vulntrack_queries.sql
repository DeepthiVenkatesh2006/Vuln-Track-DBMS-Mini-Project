-- =========================================================
-- VulnTrack: demo queries (30)
-- Format used by the web app's "Queries" page (it reads this file):
--   -- Q<nn> | <Category> | <Title>
--   -- <one-line explanation>
--   <SQL ending with ;>
-- Run AFTER ddl + dml + objects.
-- =========================================================
USE vulntrack;

-- ================= A. BASIC SELECT / FILTER =================

-- Q01 | Basic | Critical and High vulnerabilities, worst first
-- Simple WHERE + IN + ORDER BY on the catalogue.
SELECT cve_id, severity, cvss_score, description
FROM VULNERABILITY
WHERE severity IN ('Critical', 'High')
ORDER BY cvss_score DESC, cve_id;

-- Q02 | Basic | Remote-code-execution CVEs published since 2020
-- Pattern matching (LIKE) combined with a date filter.
SELECT cve_id, published_date, description
FROM VULNERABILITY
WHERE description LIKE '%Remote Code Execution%' AND published_date >= '2020-01-01'
ORDER BY published_date;

-- Q03 | Basic | Servers owned by IT Infrastructure
-- Filter on two columns.
SELECT asset_id, name, ip_address, os_version
FROM ASSET
WHERE type = 'Server' AND owner_dept = 'IT Infrastructure'
ORDER BY name;

-- ================= B. JOINS =================

-- Q04 | Join | Current state of every finding (latest scan per asset+CVE)
-- 3-table join through the v_latest_scan view; old scan rows are history, this is "now".
SELECT a.name AS asset, v.cve_id, v.severity, ls.detection_status, ls.scan_date AS last_scan, ls.scanner_used
FROM v_latest_scan ls
JOIN ASSET a         ON a.asset_id = ls.asset_id
JOIN VULNERABILITY v ON v.vuln_id  = ls.vuln_id
ORDER BY a.name, v.cvss_score DESC;

-- Q05 | Join | HEADLINE: Critical findings still open for more than 30 days
-- Fixed version of the original query: uses LATEST scan only (no duplicates) and counts days from FIRST detection.
SELECT asset_name, cve_id, severity, first_detected, days_exposed, patch_state
FROM v_open_exposure
WHERE severity = 'Critical' AND days_exposed > 30
ORDER BY days_exposed DESC;

-- Q06 | Join | Every vulnerability with its patch (LEFT JOIN shows unpatched ones as NULL)
-- LEFT JOIN keeps vulnerabilities that have no patch row.
SELECT v.cve_id, v.severity, p.description AS patch, p.release_date
FROM VULNERABILITY v
LEFT JOIN PATCH p ON p.vuln_id = v.vuln_id
ORDER BY v.cvss_score DESC;

-- Q07 | Join | Patch status per asset
-- 4-table join across both junction tables' targets.
SELECT a.name AS asset, v.cve_id, p.description AS patch, ps.patch_status, ps.applied_date
FROM PATCH_STATUS ps
JOIN ASSET a         ON a.asset_id = ps.asset_id
JOIN PATCH p         ON p.patch_id = ps.patch_id
JOIN VULNERABILITY v ON v.vuln_id  = p.vuln_id
ORDER BY a.name, v.cve_id;

-- ================= C. AGGREGATES =================

-- Q08 | Aggregate | Open findings per department
-- GROUP BY with COUNT, SUM of a boolean and MAX.
SELECT owner_dept, COUNT(*) AS open_findings, SUM(severity = 'Critical') AS critical,
       SUM(sla_breached) AS sla_breaches, MAX(cvss_score) AS worst_cvss
FROM v_open_exposure
GROUP BY owner_dept
ORDER BY open_findings DESC;

-- Q09 | Aggregate | Vulnerability catalogue by severity
-- COUNT / AVG per group.
SELECT severity, COUNT(*) AS cves, ROUND(AVG(cvss_score), 2) AS avg_cvss
FROM VULNERABILITY
GROUP BY severity
ORDER BY avg_cvss DESC;

-- Q10 | Aggregate | Patch compliance % per department
-- Share of tracked patches that are Applied.
SELECT a.owner_dept, COUNT(*) AS tracked_patches, SUM(ps.patch_status = 'Applied') AS applied,
       ROUND(100 * SUM(ps.patch_status = 'Applied') / COUNT(*), 1) AS compliance_pct
FROM PATCH_STATUS ps
JOIN ASSET a ON a.asset_id = ps.asset_id
GROUP BY a.owner_dept
ORDER BY compliance_pct;

-- Q11 | Aggregate | Assets with more than one open finding (HAVING)
-- HAVING filters groups after aggregation.
SELECT asset_name, COUNT(*) AS open_findings, SUM(cvss_score) AS total_cvss
FROM v_open_exposure
GROUP BY asset_id, asset_name
HAVING COUNT(*) > 1
ORDER BY total_cvss DESC;

-- Q12 | Aggregate | Average exposure (days) of open findings by severity
-- Aggregate on a view that itself aggregates.
SELECT severity, COUNT(*) AS findings, ROUND(AVG(days_exposed)) AS avg_days_exposed, MAX(days_exposed) AS max_days
FROM v_open_exposure
GROUP BY severity
ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low');

-- Q13 | Aggregate | Scanner comparison: volume and false-positive rate
-- Conditional aggregation.
SELECT scanner_used, COUNT(*) AS scans, SUM(detection_status = 'False Positive') AS false_positives,
       ROUND(100 * SUM(detection_status = 'False Positive') / COUNT(*), 1) AS fp_pct
FROM SCAN_RESULTS
GROUP BY scanner_used;

-- ================= D. SUBQUERIES =================

-- Q14 | Subquery | Vulnerabilities that have NO patch at all
-- NOT EXISTS (correlated subquery).
SELECT v.cve_id, v.severity, v.description
FROM VULNERABILITY v
WHERE NOT EXISTS (SELECT 1 FROM PATCH p WHERE p.vuln_id = v.vuln_id);

-- Q15 | Subquery | Assets that have never been scanned
-- NOT IN with a subquery; assets nobody has looked at are a risk too.
SELECT asset_id, name, type, owner_dept
FROM ASSET
WHERE asset_id NOT IN (SELECT asset_id FROM SCAN_RESULTS);

-- Q16 | Subquery | Assets with an open finding of the highest CVSS score in the catalogue
-- Scalar subquery (MAX) used inside WHERE.
SELECT asset_name, cve_id, cvss_score, days_exposed
FROM v_open_exposure
WHERE cvss_score = (SELECT MAX(cvss_score) FROM VULNERABILITY);

-- Q17 | Subquery | Assets riskier than the average asset
-- Subquery on a view inside HAVING-style comparison.
SELECT asset_name, owner_dept, risk_score
FROM v_asset_risk
WHERE risk_score > (SELECT AVG(risk_score) FROM v_asset_risk)
ORDER BY risk_score DESC;

-- Q18 | Subquery | Vulnerabilities seen on more than one asset
-- IN + GROUP BY/HAVING subquery: spots widespread problems.
SELECT v.cve_id, v.severity, v.description
FROM VULNERABILITY v
WHERE v.vuln_id IN (SELECT vuln_id FROM v_latest_scan
                    WHERE detection_status = 'Open'
                    GROUP BY vuln_id HAVING COUNT(DISTINCT asset_id) > 1);

-- ================= E. WINDOW FUNCTIONS =================

-- Q19 | Window | Rank assets by risk score
-- RANK() OVER; ties share a rank.
SELECT RANK() OVER (ORDER BY risk_score DESC) AS risk_rank, asset_name, owner_dept, risk_score, open_findings
FROM v_asset_risk
ORDER BY risk_rank, asset_name;

-- Q20 | Window | Scan history with the previous status (LAG)
-- Shows how each finding changed from scan to scan.
SELECT a.name AS asset, v.cve_id, sr.scan_date, sr.detection_status,
       LAG(sr.detection_status) OVER (PARTITION BY sr.asset_id, sr.vuln_id ORDER BY sr.scan_date) AS previous_status
FROM SCAN_RESULTS sr
JOIN ASSET a         ON a.asset_id = sr.asset_id
JOIN VULNERABILITY v ON v.vuln_id  = sr.vuln_id
ORDER BY a.name, v.cve_id, sr.scan_date;

-- Q21 | Window | Findings detected per month with a running total
-- GROUP BY month inside a derived table, SUM() OVER for the cumulative column.
SELECT month, new_findings, SUM(new_findings) OVER (ORDER BY month) AS running_total
FROM (SELECT DATE_FORMAT(first_scan, '%Y-%m') AS month, COUNT(*) AS new_findings
      FROM (SELECT asset_id, vuln_id, MIN(scan_date) AS first_scan
            FROM SCAN_RESULTS GROUP BY asset_id, vuln_id) f
      GROUP BY DATE_FORMAT(first_scan, '%Y-%m')) m
ORDER BY month;

-- ================= F. SET OPERATIONS / LOGIC =================

-- Q22 | Set | Patches needing attention: Failed or Pending (UNION)
-- UNION merges two filtered result sets under one label column.
SELECT a.name AS asset, p.description AS patch, 'FAILED - retry/investigate' AS action
FROM PATCH_STATUS ps JOIN ASSET a ON a.asset_id = ps.asset_id JOIN PATCH p ON p.patch_id = ps.patch_id
WHERE ps.patch_status = 'Failed'
UNION
SELECT a.name, p.description, 'Pending - schedule'
FROM PATCH_STATUS ps JOIN ASSET a ON a.asset_id = ps.asset_id JOIN PATCH p ON p.patch_id = ps.patch_id
WHERE ps.patch_status = 'Pending'
ORDER BY action, asset;

-- Q23 | Set | Assets with BOTH a Critical and a High open finding (intersection via EXISTS)
-- MySQL has no INTERSECT before 8.0.31, so two EXISTS do the job.
SELECT a.name, a.owner_dept
FROM ASSET a
WHERE EXISTS (SELECT 1 FROM v_open_exposure e WHERE e.asset_id = a.asset_id AND e.severity = 'Critical')
  AND EXISTS (SELECT 1 FROM v_open_exposure e WHERE e.asset_id = a.asset_id AND e.severity = 'High');

-- Q24 | Set | Department x severity matrix of open findings (pivot with CASE)
-- Conditional aggregation turns rows into columns.
SELECT owner_dept,
       SUM(severity = 'Critical') AS critical, SUM(severity = 'High') AS high,
       SUM(severity = 'Medium')   AS medium,   SUM(severity = 'Low')  AS low
FROM v_open_exposure
GROUP BY owner_dept;

-- ================= G. BUSINESS / MONITORING =================

-- Q25 | Business | SLA breaches (open longer than the severity's deadline)
-- Uses fn_sla_days() through the view: Critical 7d, High 30d, Medium 60d, Low 90d.
SELECT asset_name, cve_id, severity, days_exposed, sla_days, days_exposed - sla_days AS days_overdue, patch_state
FROM v_open_exposure
WHERE sla_breached = 1
ORDER BY days_overdue DESC;

-- Q26 | Business | Patched but not verified (patch Applied, latest scan still Open)
-- Needs a re-scan to close the finding.
SELECT asset_name, cve_id, severity, last_scanned
FROM v_open_exposure
WHERE patch_state = 'Applied';

-- Q27 | Business | Findings with no vendor patch available (need mitigation instead)
-- Filter on the derived patch_state column.
SELECT asset_name, cve_id, severity, days_exposed
FROM v_open_exposure
WHERE patch_state = 'No patch available'
ORDER BY days_exposed DESC;

-- Q28 | Business | Risk score per asset using the stored function fn_asset_risk()
-- Calls a user-defined function row by row.
SELECT asset_id, name, owner_dept, fn_asset_risk(asset_id) AS risk_score
FROM ASSET
ORDER BY risk_score DESC;

-- Q29 | Business | Top 3 most exposed assets
-- ORDER BY + LIMIT on the view.
SELECT asset_name, owner_dept, open_findings, critical_open, risk_score
FROM v_asset_risk
ORDER BY risk_score DESC
LIMIT 3;

-- Q30 | Business | Full report for one asset via stored procedure (DomainController-01)
-- CALL returns a result set from sp_asset_report().
CALL sp_asset_report(8);
