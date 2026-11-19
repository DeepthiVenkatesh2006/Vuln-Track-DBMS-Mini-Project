-- =========================================================
-- VulnTrack: DML (sample data)
-- Run AFTER vulntrack_ddl.sql.
-- Real, publicly-known CVEs (CVSS v3 scores as listed by NVD, approximate)
-- + synthetic asset / patch / scan data.  Data is illustrative, not a real network.
-- [CHANGED] severity is no longer inserted (it is computed from cvss_score).
-- [CHANGED] vulnerabilities now sit on assets where they make sense
--           (Zerologon on a domain controller, not an HR PC; BlueKeep on a Windows server, not a router).
-- [CHANGED] patched findings now have a later 'Resolved' re-scan row, so history is realistic.
-- =========================================================

USE vulntrack;

-- ---------------------------------------------------------
-- 1. ASSET   (ids 1..11 follow insertion order)
-- ---------------------------------------------------------
INSERT INTO ASSET (name, type, ip_address, owner_dept, os_version) VALUES
('WebServer-01',      'Server',  '192.168.1.10', 'IT Infrastructure', 'Ubuntu 22.04 LTS'),      -- 1
('DBServer-01',       'Server',  '192.168.1.11', 'IT Infrastructure', 'CentOS 8'),              -- 2
('DevLaptop-14',      'Laptop',  '192.168.2.34', 'Engineering',       'Windows 11 Pro'),        -- 3
('DevLaptop-15',      'Laptop',  '192.168.2.35', 'Engineering',       'macOS Sonoma'),          -- 4
('CoreRouter-01',     'Router',  '192.168.0.1',  'Network Ops',       'Cisco IOS 15.2'),        -- 5
('HR-Workstation-03', 'Desktop', '192.168.3.21', 'HR',                'Windows 10 Pro'),        -- 6
('AppServer-02',      'Server',  '192.168.1.12', 'IT Infrastructure', 'Ubuntu 20.04 LTS'),      -- 7
('DomainController-01','Server', '192.168.1.5',  'IT Infrastructure', 'Windows Server 2016'),   -- 8
('FileServer-01',     'Server',  '192.168.1.13', 'IT Infrastructure', 'Windows Server 2012 R2'),-- 9
('MailServer-01',     'Server',  '192.168.1.14', 'IT Infrastructure', 'Windows Server 2019'),   -- 10
('Finance-Desktop-02','Desktop', '192.168.3.40', 'Finance',           'Windows 10 Pro');        -- 11

-- ---------------------------------------------------------
-- 2. VULNERABILITY  (13 CVEs: 5 Critical, 6 High, 1 Medium, 1 Low after banding)
-- ---------------------------------------------------------
INSERT INTO VULNERABILITY (cve_id, description, cvss_score, published_date) VALUES
('CVE-2021-44228', 'Apache Log4j2 Remote Code Execution (Log4Shell)',            10.0, '2021-12-10'),
('CVE-2014-0160',  'OpenSSL Heartbleed - information disclosure',                  7.5, '2014-04-07'),
('CVE-2017-0144',  'Windows SMBv1 Remote Code Execution (EternalBlue)',            8.1, '2017-03-14'),
('CVE-2019-0708',  'Windows RDP Remote Code Execution (BlueKeep)',                 9.8, '2019-05-14'),
('CVE-2020-1472',  'Netlogon Elevation of Privilege (Zerologon)',                 10.0, '2020-08-11'),
('CVE-2022-22965', 'Spring Framework Remote Code Execution (Spring4Shell)',        9.8, '2022-03-31'),
('CVE-2018-11776', 'Apache Struts2 Remote Code Execution',                         8.1, '2018-08-22'),
('CVE-2021-34527', 'Windows Print Spooler Remote Code Execution (PrintNightmare)', 8.8, '2021-07-02'),
('CVE-2021-3156',  'sudo heap overflow privilege escalation (Baron Samedit)',      7.8, '2021-01-26'),
('CVE-2021-26855', 'Microsoft Exchange Server SSRF (ProxyLogon)',                  9.8, '2021-03-02'),
('CVE-2022-30190', 'Microsoft Windows Support Diagnostic Tool RCE (Follina)',      7.8, '2022-06-01'),
('CVE-2011-3389',  'TLS 1.0 CBC plaintext recovery (BEAST)',                       5.9, '2011-09-06'),
('CVE-2015-4000',  'TLS Diffie-Hellman weak parameters downgrade (Logjam)',        3.7, '2015-05-21');

-- ---------------------------------------------------------
-- 3. PATCH  (tied to vuln_id via subquery on cve_id)
-- ---------------------------------------------------------
INSERT INTO PATCH (vuln_id, release_date, description) VALUES
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-44228'), '2021-12-13', 'Log4j 2.15.0 upgrade'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2014-0160'),  '2014-04-08', 'OpenSSL 1.0.1g upgrade'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2017-0144'),  '2017-03-14', 'MS17-010 security update'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2019-0708'),  '2019-05-14', 'RDP security patch KB4499175'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2020-1472'),  '2020-08-11', 'Netlogon security update KB4557222'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2022-22965'), '2022-03-31', 'Spring Framework 5.3.18 upgrade'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-34527'), '2021-07-06', 'Print Spooler update KB5004945'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-3156'),  '2021-01-26', 'sudo 1.9.5p2 upgrade'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-26855'), '2021-03-02', 'Exchange Server March 2021 security update'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2022-30190'), '2022-06-14', 'June 2022 cumulative update'),
((SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2011-3389'),  NULL,         'Disable TLS 1.0 via group policy (configuration fix)');
-- CVE-2018-11776 (Struts) and CVE-2015-4000 (Logjam) intentionally have NO patch row
-- -> they show up as "no patch available" in the demo queries.

-- ---------------------------------------------------------
-- 4. SCAN_RESULTS  (asset_id, vuln via cve, scan_date, scanner, status)
--    A finding that was fixed has a later 'Resolved' row; the OLD 'Open' row is kept as history.
-- ---------------------------------------------------------
INSERT INTO SCAN_RESULTS (asset_id, vuln_id, scan_date, scanner_used, detection_status) VALUES
(1,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-44228'), '2026-08-01', 'Nessus',  'Open'),
(1,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-44228'), '2026-08-12', 'Nessus',  'Resolved'),
(1,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2018-11776'), '2026-07-01', 'Nessus',  'Open'),
(2,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2014-0160'),  '2026-08-01', 'Nessus',  'Open'),
(2,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2014-0160'),  '2026-08-07', 'Nessus',  'Resolved'),
(2,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-3156'),  '2026-10-05', 'OpenVAS', 'Open'),
(3,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2022-30190'), '2026-09-10', 'OpenVAS', 'Open'),
(3,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2022-30190'), '2026-09-15', 'OpenVAS', 'Resolved'),
(6,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2017-0144'),  '2026-08-02', 'OpenVAS', 'Open'),
(6,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-34527'), '2026-09-20', 'Nessus',  'Open'),
(7,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2022-22965'), '2026-08-05', 'OpenVAS', 'Open'),
(7,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2022-22965'), '2026-08-08', 'OpenVAS', 'Resolved'),
(7,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-3156'),  '2026-10-05', 'Nessus',  'Open'),
(8,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2020-1472'),  '2026-07-15', 'Nessus',  'Open'),
(8,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-34527'), '2026-09-20', 'Nessus',  'Open'),
(9,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2019-0708'),  '2026-08-02', 'OpenVAS', 'Open'),
(9,  (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2011-3389'),  '2026-10-01', 'OpenVAS', 'Open'),
(10, (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2021-26855'), '2026-09-01', 'Nessus',  'Open'),
(11, (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2015-4000'),  '2026-10-10', 'Nessus',  'Open'),
(11, (SELECT vuln_id FROM VULNERABILITY WHERE cve_id='CVE-2011-3389'),  '2026-10-10', 'Nessus',  'False Positive');
-- Assets 4 (macOS laptop) and 5 (router) have never been scanned -> used by the "never scanned" query.

-- ---------------------------------------------------------
-- 5. PATCH_STATUS  (has each asset actually applied the relevant patch?)
-- ---------------------------------------------------------
INSERT INTO PATCH_STATUS (asset_id, patch_id, applied_date, patch_status) VALUES
(1,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2021-44228'), '2026-08-10', 'Applied'),
(2,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2014-0160'),  '2026-08-05', 'Applied'),
(2,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2021-3156'),  NULL,         'Pending'),
(3,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2022-30190'), '2026-09-14', 'Applied'),
(6,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2017-0144'),  NULL,         'Pending'),
(6,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2021-34527'), NULL,         'Pending'),
(7,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2022-22965'), '2026-08-06', 'Applied'),
(7,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2021-3156'),  NULL,         'Pending'),
(8,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2020-1472'),  NULL,         'Pending'),
(8,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2021-34527'), NULL,         'Failed'),
(9,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2019-0708'),  NULL,         'Failed'),
(9,  (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2011-3389'),  NULL,         'Pending'),
(10, (SELECT p.patch_id FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE v.cve_id='CVE-2021-26855'), '2026-09-03', 'Applied');
-- Asset 10 / ProxyLogon: patch Applied 3 Sep but NOT re-scanned yet -> "patched but unverified" demo.
