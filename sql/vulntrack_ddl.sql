-- =========================================================
-- VulnTrack: DDL (table structure)
-- Same 5 tables as the original design. Changes are marked  [CHANGED]/[NEW].
-- Run order: ddl -> dml -> objects  (see README)
-- =========================================================
DROP DATABASE IF EXISTS vulntrack;
CREATE DATABASE vulntrack;
USE vulntrack;

-- 1. ASSET
CREATE TABLE ASSET (
    asset_id     INT AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    type         VARCHAR(50)  NOT NULL,
    ip_address   VARCHAR(45)  UNIQUE,
    owner_dept   VARCHAR(100),
    os_version   VARCHAR(100),
    INDEX idx_asset_dept (owner_dept)                       -- [NEW] dept reports
);

-- 2. VULNERABILITY
-- [CHANGED] severity is now DERIVED from cvss_score (generated column), so the two
-- can never disagree (EternalBlue 8.1 was wrongly stored as 'Critical') and the
-- table really is in 3NF. Bands follow CVSS v3: 9.0+ Critical, 7.0+ High, 4.0+ Medium, else Low.
CREATE TABLE VULNERABILITY (
    vuln_id        INT AUTO_INCREMENT PRIMARY KEY,
    cve_id         VARCHAR(20) UNIQUE NOT NULL,
    description    TEXT,
    cvss_score     DECIMAL(3,1) NOT NULL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    severity       VARCHAR(10) GENERATED ALWAYS AS (
                       CASE WHEN cvss_score >= 9.0 THEN 'Critical'
                            WHEN cvss_score >= 7.0 THEN 'High'
                            WHEN cvss_score >= 4.0 THEN 'Medium'
                            ELSE 'Low' END) STORED,
    published_date DATE,
    INDEX idx_vuln_severity (severity)                      -- [NEW]
);

-- 3. PATCH   (1 vulnerability : N patches -- kept as in the original ER design)
CREATE TABLE PATCH (
    patch_id     INT AUTO_INCREMENT PRIMARY KEY,
    vuln_id      INT NOT NULL,
    release_date DATE,
    description  TEXT,
    FOREIGN KEY (vuln_id) REFERENCES VULNERABILITY(vuln_id)
        ON DELETE CASCADE
);

-- 4. SCAN_RESULTS (junction: ASSET <-> VULNERABILITY, history kept via scan_date)
CREATE TABLE SCAN_RESULTS (
    asset_id         INT NOT NULL,
    vuln_id          INT NOT NULL,
    scan_date        DATE NOT NULL,
    scanner_used     VARCHAR(100),
    detection_status ENUM('Open','Resolved','False Positive') DEFAULT 'Open',
    PRIMARY KEY (asset_id, vuln_id, scan_date),
    FOREIGN KEY (asset_id) REFERENCES ASSET(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (vuln_id)  REFERENCES VULNERABILITY(vuln_id) ON DELETE CASCADE
);

-- 5. PATCH_STATUS (junction: ASSET <-> PATCH)
-- [CHANGED] CHECK: a patch marked 'Applied' must carry an applied_date.
CREATE TABLE PATCH_STATUS (
    asset_id     INT NOT NULL,
    patch_id     INT NOT NULL,
    applied_date DATE,
    patch_status ENUM('Pending','Applied','Failed') DEFAULT 'Pending',
    PRIMARY KEY (asset_id, patch_id),
    FOREIGN KEY (asset_id) REFERENCES ASSET(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (patch_id) REFERENCES PATCH(patch_id) ON DELETE CASCADE,
    CHECK (patch_status <> 'Applied' OR applied_date IS NOT NULL)
);

-- 6. [NEW] PATCH_STATUS_LOG (audit trail, filled by triggers). Moved here from the
-- "optional" section so a plain DDL run always creates it. No FKs on purpose:
-- the log must survive deletion of the asset/patch it describes.
CREATE TABLE PATCH_STATUS_LOG (
    log_id      INT AUTO_INCREMENT PRIMARY KEY,
    asset_id    INT,
    patch_id    INT,
    old_status  VARCHAR(20),
    new_status  VARCHAR(20),
    changed_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 7. [NEW] APP_USER (web-app login accounts for role-based access control).
-- Passwords are stored as salted hashes (werkzeug), never in plain text.
-- Roles: viewer (read-only) < analyst (records scans / patch status / advisories / notes) < admin (everything + users).
-- The seed accounts are created by app/setup_db.py because the hashes are generated in Python.
CREATE TABLE APP_USER (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('viewer','analyst','admin') NOT NULL DEFAULT 'viewer',
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME     NULL
);
