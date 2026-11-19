# VulnTrack - query outputs
Captured from a real run on MariaDB 10.11 on 2026-10-27 (CURDATE-based columns such as `days_exposed` change daily). SQL text lives in `sql/vulntrack_queries.sql`.

## Q01 - Critical and High vulnerabilities, worst first
*Basic. Simple WHERE + IN + ORDER BY on the catalogue.*

```sql
SELECT cve_id, severity, cvss_score, description
FROM VULNERABILITY
WHERE severity IN ('Critical', 'High')
ORDER BY cvss_score DESC, cve_id;
```
| cve_id | severity | cvss_score | description |
|---|---|---|---|
| CVE-2020-1472 | Critical | 10.0 | Netlogon Elevation of Privilege (Zerologon) |
| CVE-2021-44228 | Critical | 10.0 | Apache Log4j2 Remote Code Execution (Log4Shell) |
| CVE-2019-0708 | Critical | 9.8 | Windows RDP Remote Code Execution (BlueKeep) |
| CVE-2021-26855 | Critical | 9.8 | Microsoft Exchange Server SSRF (ProxyLogon) |
| CVE-2022-22965 | Critical | 9.8 | Spring Framework Remote Code Execution (Spring4Shell) |
| CVE-2021-34527 | High | 8.8 | Windows Print Spooler Remote Code Execution (PrintNightmare) |
| CVE-2017-0144 | High | 8.1 | Windows SMBv1 Remote Code Execution (EternalBlue) |
| CVE-2018-11776 | High | 8.1 | Apache Struts2 Remote Code Execution |
| CVE-2021-3156 | High | 7.8 | sudo heap overflow privilege escalation (Baron Samedit) |
| CVE-2022-30190 | High | 7.8 | Microsoft Windows Support Diagnostic Tool RCE (Follina) |
| CVE-2014-0160 | High | 7.5 | OpenSSL Heartbleed - information disclosure |

11 row(s)

## Q02 - Remote-code-execution CVEs published since 2020
*Basic. Pattern matching (LIKE) combined with a date filter.*

```sql
SELECT cve_id, published_date, description
FROM VULNERABILITY
WHERE description LIKE '%Remote Code Execution%' AND published_date >= '2020-01-01'
ORDER BY published_date;
```
| cve_id | published_date | description |
|---|---|---|
| CVE-2021-34527 | 2021-07-02 | Windows Print Spooler Remote Code Execution (PrintNightmare) |
| CVE-2021-44228 | 2021-12-10 | Apache Log4j2 Remote Code Execution (Log4Shell) |
| CVE-2022-22965 | 2022-03-31 | Spring Framework Remote Code Execution (Spring4Shell) |

3 row(s)

## Q03 - Servers owned by IT Infrastructure
*Basic. Filter on two columns.*

```sql
SELECT asset_id, name, ip_address, os_version
FROM ASSET
WHERE type = 'Server' AND owner_dept = 'IT Infrastructure'
ORDER BY name;
```
| asset_id | name | ip_address | os_version |
|---|---|---|---|
| 7 | AppServer-02 | 192.168.1.12 | Ubuntu 20.04 LTS |
| 2 | DBServer-01 | 192.168.1.11 | CentOS 8 |
| 8 | DomainController-01 | 192.168.1.5 | Windows Server 2016 |
| 9 | FileServer-01 | 192.168.1.13 | Windows Server 2012 R2 |
| 10 | MailServer-01 | 192.168.1.14 | Windows Server 2019 |
| 1 | WebServer-01 | 192.168.1.10 | Ubuntu 22.04 LTS |

6 row(s)

## Q04 - Current state of every finding (latest scan per asset+CVE)
*Join. 3-table join through the v_latest_scan view; old scan rows are history, this is "now".*

```sql
SELECT a.name AS asset, v.cve_id, v.severity, ls.detection_status, ls.scan_date AS last_scan, ls.scanner_used
FROM v_latest_scan ls
JOIN ASSET a         ON a.asset_id = ls.asset_id
JOIN VULNERABILITY v ON v.vuln_id  = ls.vuln_id
ORDER BY a.name, v.cvss_score DESC;
```
| asset | cve_id | severity | detection_status | last_scan | scanner_used |
|---|---|---|---|---|---|
| AppServer-02 | CVE-2022-22965 | Critical | Resolved | 2026-08-08 | OpenVAS |
| AppServer-02 | CVE-2021-3156 | High | Open | 2026-10-05 | Nessus |
| DBServer-01 | CVE-2021-3156 | High | Open | 2026-10-05 | OpenVAS |
| DBServer-01 | CVE-2014-0160 | High | Resolved | 2026-08-07 | Nessus |
| DevLaptop-14 | CVE-2022-30190 | High | Resolved | 2026-09-15 | OpenVAS |
| DomainController-01 | CVE-2020-1472 | Critical | Open | 2026-07-15 | Nessus |
| DomainController-01 | CVE-2021-34527 | High | Open | 2026-09-20 | Nessus |
| FileServer-01 | CVE-2019-0708 | Critical | Open | 2026-08-02 | OpenVAS |
| FileServer-01 | CVE-2011-3389 | Medium | Open | 2026-10-01 | OpenVAS |
| Finance-Desktop-02 | CVE-2011-3389 | Medium | False Positive | 2026-10-10 | Nessus |
| Finance-Desktop-02 | CVE-2015-4000 | Low | Open | 2026-10-10 | Nessus |
| HR-Workstation-03 | CVE-2021-34527 | High | Open | 2026-09-20 | Nessus |
| HR-Workstation-03 | CVE-2017-0144 | High | Open | 2026-08-02 | OpenVAS |
| MailServer-01 | CVE-2021-26855 | Critical | Open | 2026-09-01 | Nessus |
| WebServer-01 | CVE-2021-44228 | Critical | Resolved | 2026-08-12 | Nessus |
| WebServer-01 | CVE-2018-11776 | High | Open | 2026-07-01 | Nessus |

16 row(s)

## Q05 - HEADLINE: Critical findings still open for more than 30 days
*Join. Fixed version of the original query: uses LATEST scan only (no duplicates) and counts days from FIRST detection.*

```sql
SELECT asset_name, cve_id, severity, first_detected, days_exposed, patch_state
FROM v_open_exposure
WHERE severity = 'Critical' AND days_exposed > 30
ORDER BY days_exposed DESC;
```
| asset_name | cve_id | severity | first_detected | days_exposed | patch_state |
|---|---|---|---|---|---|
| DomainController-01 | CVE-2020-1472 | Critical | 2026-07-15 | 104 | Pending |
| FileServer-01 | CVE-2019-0708 | Critical | 2026-08-02 | 86 | Failed |
| MailServer-01 | CVE-2021-26855 | Critical | 2026-09-01 | 56 | Applied |

3 row(s)

## Q06 - Every vulnerability with its patch (LEFT JOIN shows unpatched ones as NULL)
*Join. LEFT JOIN keeps vulnerabilities that have no patch row.*

```sql
SELECT v.cve_id, v.severity, p.description AS patch, p.release_date
FROM VULNERABILITY v
LEFT JOIN PATCH p ON p.vuln_id = v.vuln_id
ORDER BY v.cvss_score DESC;
```
| cve_id | severity | patch | release_date |
|---|---|---|---|
| CVE-2021-44228 | Critical | Log4j 2.15.0 upgrade | 2021-12-13 |
| CVE-2020-1472 | Critical | Netlogon security update KB4557222 | 2020-08-11 |
| CVE-2021-26855 | Critical | Exchange Server March 2021 security update | 2021-03-02 |
| CVE-2019-0708 | Critical | RDP security patch KB4499175 | 2019-05-14 |
| CVE-2022-22965 | Critical | Spring Framework 5.3.18 upgrade | 2022-03-31 |
| CVE-2021-34527 | High | Print Spooler update KB5004945 | 2021-07-06 |
| CVE-2018-11776 | High |  |  |
| CVE-2017-0144 | High | MS17-010 security update | 2017-03-14 |
| CVE-2021-3156 | High | sudo 1.9.5p2 upgrade | 2021-01-26 |
| CVE-2022-30190 | High | June 2022 cumulative update | 2022-06-14 |
| CVE-2014-0160 | High | OpenSSL 1.0.1g upgrade | 2014-04-08 |
| CVE-2011-3389 | Medium | Disable TLS 1.0 via group policy (configuration fix) |  |
| CVE-2015-4000 | Low |  |  |

13 row(s)

## Q07 - Patch status per asset
*Join. 4-table join across both junction tables' targets.*

```sql
SELECT a.name AS asset, v.cve_id, p.description AS patch, ps.patch_status, ps.applied_date
FROM PATCH_STATUS ps
JOIN ASSET a         ON a.asset_id = ps.asset_id
JOIN PATCH p         ON p.patch_id = ps.patch_id
JOIN VULNERABILITY v ON v.vuln_id  = p.vuln_id
ORDER BY a.name, v.cve_id;
```
| asset | cve_id | patch | patch_status | applied_date |
|---|---|---|---|---|
| AppServer-02 | CVE-2021-3156 | sudo 1.9.5p2 upgrade | Pending |  |
| AppServer-02 | CVE-2022-22965 | Spring Framework 5.3.18 upgrade | Applied | 2026-08-06 |
| DBServer-01 | CVE-2014-0160 | OpenSSL 1.0.1g upgrade | Applied | 2026-08-05 |
| DBServer-01 | CVE-2021-3156 | sudo 1.9.5p2 upgrade | Pending |  |
| DevLaptop-14 | CVE-2022-30190 | June 2022 cumulative update | Applied | 2026-09-14 |
| DomainController-01 | CVE-2020-1472 | Netlogon security update KB4557222 | Pending |  |
| DomainController-01 | CVE-2021-34527 | Print Spooler update KB5004945 | Failed |  |
| FileServer-01 | CVE-2011-3389 | Disable TLS 1.0 via group policy (configuration fix) | Pending |  |
| FileServer-01 | CVE-2019-0708 | RDP security patch KB4499175 | Failed |  |
| HR-Workstation-03 | CVE-2017-0144 | MS17-010 security update | Pending |  |
| HR-Workstation-03 | CVE-2021-34527 | Print Spooler update KB5004945 | Pending |  |
| MailServer-01 | CVE-2021-26855 | Exchange Server March 2021 security update | Applied | 2026-09-03 |
| WebServer-01 | CVE-2021-44228 | Log4j 2.15.0 upgrade | Applied | 2026-08-10 |

13 row(s)

## Q08 - Open findings per department
*Aggregate. GROUP BY with COUNT, SUM of a boolean and MAX.*

```sql
SELECT owner_dept, COUNT(*) AS open_findings, SUM(severity = 'Critical') AS critical,
       SUM(sla_breached) AS sla_breaches, MAX(cvss_score) AS worst_cvss
FROM v_open_exposure
GROUP BY owner_dept
ORDER BY open_findings DESC;
```
| owner_dept | open_findings | critical | sla_breaches | worst_cvss |
|---|---|---|---|---|
| IT Infrastructure | 8 | 3 | 5 | 10.0 |
| HR | 2 | 0 | 2 | 8.8 |
| Finance | 1 | 0 | 0 | 3.7 |

3 row(s)

## Q09 - Vulnerability catalogue by severity
*Aggregate. COUNT / AVG per group.*

```sql
SELECT severity, COUNT(*) AS cves, ROUND(AVG(cvss_score), 2) AS avg_cvss
FROM VULNERABILITY
GROUP BY severity
ORDER BY avg_cvss DESC;
```
| severity | cves | avg_cvss |
|---|---|---|
| Critical | 5 | 9.88 |
| High | 6 | 8.02 |
| Medium | 1 | 5.90 |
| Low | 1 | 3.70 |

4 row(s)

## Q10 - Patch compliance % per department
*Aggregate. Share of tracked patches that are Applied.*

```sql
SELECT a.owner_dept, COUNT(*) AS tracked_patches, SUM(ps.patch_status = 'Applied') AS applied,
       ROUND(100 * SUM(ps.patch_status = 'Applied') / COUNT(*), 1) AS compliance_pct
FROM PATCH_STATUS ps
JOIN ASSET a ON a.asset_id = ps.asset_id
GROUP BY a.owner_dept
ORDER BY compliance_pct;
```
| owner_dept | tracked_patches | applied | compliance_pct |
|---|---|---|---|
| HR | 2 | 0 | 0.0 |
| IT Infrastructure | 10 | 4 | 40.0 |
| Engineering | 1 | 1 | 100.0 |

3 row(s)

## Q11 - Assets with more than one open finding (HAVING)
*Aggregate. HAVING filters groups after aggregation.*

```sql
SELECT asset_name, COUNT(*) AS open_findings, SUM(cvss_score) AS total_cvss
FROM v_open_exposure
GROUP BY asset_id, asset_name
HAVING COUNT(*) > 1
ORDER BY total_cvss DESC;
```
| asset_name | open_findings | total_cvss |
|---|---|---|
| DomainController-01 | 2 | 18.8 |
| HR-Workstation-03 | 2 | 16.9 |
| FileServer-01 | 2 | 15.7 |

3 row(s)

## Q12 - Average exposure (days) of open findings by severity
*Aggregate. Aggregate on a view that itself aggregates.*

```sql
SELECT severity, COUNT(*) AS findings, ROUND(AVG(days_exposed)) AS avg_days_exposed, MAX(days_exposed) AS max_days
FROM v_open_exposure
GROUP BY severity
ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low');
```
| severity | findings | avg_days_exposed | max_days |
|---|---|---|---|
| Critical | 3 | 82 | 104 |
| High | 6 | 54 | 118 |
| Medium | 1 | 26 | 26 |
| Low | 1 | 17 | 17 |

4 row(s)

## Q13 - Scanner comparison: volume and false-positive rate
*Aggregate. Conditional aggregation.*

```sql
SELECT scanner_used, COUNT(*) AS scans, SUM(detection_status = 'False Positive') AS false_positives,
       ROUND(100 * SUM(detection_status = 'False Positive') / COUNT(*), 1) AS fp_pct
FROM SCAN_RESULTS
GROUP BY scanner_used;
```
| scanner_used | scans | false_positives | fp_pct |
|---|---|---|---|
| Nessus | 12 | 1 | 8.3 |
| OpenVAS | 8 | 0 | 0.0 |

2 row(s)

## Q14 - Vulnerabilities that have NO patch at all
*Subquery. NOT EXISTS (correlated subquery).*

```sql
SELECT v.cve_id, v.severity, v.description
FROM VULNERABILITY v
WHERE NOT EXISTS (SELECT 1 FROM PATCH p WHERE p.vuln_id = v.vuln_id);
```
| cve_id | severity | description |
|---|---|---|
| CVE-2018-11776 | High | Apache Struts2 Remote Code Execution |
| CVE-2015-4000 | Low | TLS Diffie-Hellman weak parameters downgrade (Logjam) |

2 row(s)

## Q15 - Assets that have never been scanned
*Subquery. NOT IN with a subquery; assets nobody has looked at are a risk too.*

```sql
SELECT asset_id, name, type, owner_dept
FROM ASSET
WHERE asset_id NOT IN (SELECT asset_id FROM SCAN_RESULTS);
```
| asset_id | name | type | owner_dept |
|---|---|---|---|
| 4 | DevLaptop-15 | Laptop | Engineering |
| 5 | CoreRouter-01 | Router | Network Ops |

2 row(s)

## Q16 - Assets with an open finding of the highest CVSS score in the catalogue
*Subquery. Scalar subquery (MAX) used inside WHERE.*

```sql
SELECT asset_name, cve_id, cvss_score, days_exposed
FROM v_open_exposure
WHERE cvss_score = (SELECT MAX(cvss_score) FROM VULNERABILITY);
```
| asset_name | cve_id | cvss_score | days_exposed |
|---|---|---|---|
| DomainController-01 | CVE-2020-1472 | 10.0 | 104 |

1 row(s)

## Q17 - Assets riskier than the average asset
*Subquery. Subquery on a view inside HAVING-style comparison.*

```sql
SELECT asset_name, owner_dept, risk_score
FROM v_asset_risk
WHERE risk_score > (SELECT AVG(risk_score) FROM v_asset_risk)
ORDER BY risk_score DESC;
```
| asset_name | owner_dept | risk_score |
|---|---|---|
| DomainController-01 | IT Infrastructure | 18.8 |
| HR-Workstation-03 | HR | 16.9 |
| FileServer-01 | IT Infrastructure | 15.7 |
| MailServer-01 | IT Infrastructure | 9.8 |
| WebServer-01 | IT Infrastructure | 8.1 |

5 row(s)

## Q18 - Vulnerabilities seen on more than one asset
*Subquery. IN + GROUP BY/HAVING subquery: spots widespread problems.*

```sql
SELECT v.cve_id, v.severity, v.description
FROM VULNERABILITY v
WHERE v.vuln_id IN (SELECT vuln_id FROM v_latest_scan
                    WHERE detection_status = 'Open'
                    GROUP BY vuln_id HAVING COUNT(DISTINCT asset_id) > 1);
```
| cve_id | severity | description |
|---|---|---|
| CVE-2021-34527 | High | Windows Print Spooler Remote Code Execution (PrintNightmare) |
| CVE-2021-3156 | High | sudo heap overflow privilege escalation (Baron Samedit) |

2 row(s)

## Q19 - Rank assets by risk score
*Window. RANK() OVER; ties share a rank.*

```sql
SELECT RANK() OVER (ORDER BY risk_score DESC) AS risk_rank, asset_name, owner_dept, risk_score, open_findings
FROM v_asset_risk
ORDER BY risk_rank, asset_name;
```
| risk_rank | asset_name | owner_dept | risk_score | open_findings |
|---|---|---|---|---|
| 1 | DomainController-01 | IT Infrastructure | 18.8 | 2 |
| 2 | HR-Workstation-03 | HR | 16.9 | 2 |
| 3 | FileServer-01 | IT Infrastructure | 15.7 | 2 |
| 4 | MailServer-01 | IT Infrastructure | 9.8 | 1 |
| 5 | WebServer-01 | IT Infrastructure | 8.1 | 1 |
| 6 | AppServer-02 | IT Infrastructure | 7.8 | 1 |
| 6 | DBServer-01 | IT Infrastructure | 7.8 | 1 |
| 8 | Finance-Desktop-02 | Finance | 3.7 | 1 |
| 9 | CoreRouter-01 | Network Ops | 0.0 | 0 |
| 9 | DevLaptop-14 | Engineering | 0.0 | 0 |
| 9 | DevLaptop-15 | Engineering | 0.0 | 0 |

11 row(s)

## Q20 - Scan history with the previous status (LAG)
*Window. Shows how each finding changed from scan to scan.*

```sql
SELECT a.name AS asset, v.cve_id, sr.scan_date, sr.detection_status,
       LAG(sr.detection_status) OVER (PARTITION BY sr.asset_id, sr.vuln_id ORDER BY sr.scan_date) AS previous_status
FROM SCAN_RESULTS sr
JOIN ASSET a         ON a.asset_id = sr.asset_id
JOIN VULNERABILITY v ON v.vuln_id  = sr.vuln_id
ORDER BY a.name, v.cve_id, sr.scan_date;
```
| asset | cve_id | scan_date | detection_status | previous_status |
|---|---|---|---|---|
| AppServer-02 | CVE-2021-3156 | 2026-10-05 | Open |  |
| AppServer-02 | CVE-2022-22965 | 2026-08-05 | Open |  |
| AppServer-02 | CVE-2022-22965 | 2026-08-08 | Resolved | Open |
| DBServer-01 | CVE-2014-0160 | 2026-08-01 | Open |  |
| DBServer-01 | CVE-2014-0160 | 2026-08-07 | Resolved | Open |
| DBServer-01 | CVE-2021-3156 | 2026-10-05 | Open |  |
| DevLaptop-14 | CVE-2022-30190 | 2026-09-10 | Open |  |
| DevLaptop-14 | CVE-2022-30190 | 2026-09-15 | Resolved | Open |
| DomainController-01 | CVE-2020-1472 | 2026-07-15 | Open |  |
| DomainController-01 | CVE-2021-34527 | 2026-09-20 | Open |  |
| FileServer-01 | CVE-2011-3389 | 2026-10-01 | Open |  |
| FileServer-01 | CVE-2019-0708 | 2026-08-02 | Open |  |
| Finance-Desktop-02 | CVE-2011-3389 | 2026-10-10 | False Positive |  |
| Finance-Desktop-02 | CVE-2015-4000 | 2026-10-10 | Open |  |
| HR-Workstation-03 | CVE-2017-0144 | 2026-08-02 | Open |  |
| HR-Workstation-03 | CVE-2021-34527 | 2026-09-20 | Open |  |
| MailServer-01 | CVE-2021-26855 | 2026-09-01 | Open |  |
| WebServer-01 | CVE-2018-11776 | 2026-07-01 | Open |  |
| WebServer-01 | CVE-2021-44228 | 2026-08-01 | Open |  |
| WebServer-01 | CVE-2021-44228 | 2026-08-12 | Resolved | Open |

20 row(s)

## Q21 - Findings detected per month with a running total
*Window. GROUP BY month inside a derived table, SUM() OVER for the cumulative column.*

```sql
SELECT month, new_findings, SUM(new_findings) OVER (ORDER BY month) AS running_total
FROM (SELECT DATE_FORMAT(first_scan, '%Y-%m') AS month, COUNT(*) AS new_findings
      FROM (SELECT asset_id, vuln_id, MIN(scan_date) AS first_scan
            FROM SCAN_RESULTS GROUP BY asset_id, vuln_id) f
      GROUP BY DATE_FORMAT(first_scan, '%Y-%m')) m
ORDER BY month;
```
| month | new_findings | running_total |
|---|---|---|
| 2026-07 | 2 | 2 |
| 2026-08 | 5 | 7 |
| 2026-09 | 4 | 11 |
| 2026-10 | 5 | 16 |

4 row(s)

## Q22 - Patches needing attention: Failed or Pending (UNION)
*Set. UNION merges two filtered result sets under one label column.*

```sql
SELECT a.name AS asset, p.description AS patch, 'FAILED - retry/investigate' AS action
FROM PATCH_STATUS ps JOIN ASSET a ON a.asset_id = ps.asset_id JOIN PATCH p ON p.patch_id = ps.patch_id
WHERE ps.patch_status = 'Failed'
UNION
SELECT a.name, p.description, 'Pending - schedule'
FROM PATCH_STATUS ps JOIN ASSET a ON a.asset_id = ps.asset_id JOIN PATCH p ON p.patch_id = ps.patch_id
WHERE ps.patch_status = 'Pending'
ORDER BY action, asset;
```
| asset | patch | action |
|---|---|---|
| DomainController-01 | Print Spooler update KB5004945 | FAILED - retry/investigate |
| FileServer-01 | RDP security patch KB4499175 | FAILED - retry/investigate |
| AppServer-02 | sudo 1.9.5p2 upgrade | Pending - schedule |
| DBServer-01 | sudo 1.9.5p2 upgrade | Pending - schedule |
| DomainController-01 | Netlogon security update KB4557222 | Pending - schedule |
| FileServer-01 | Disable TLS 1.0 via group policy (configuration fix) | Pending - schedule |
| HR-Workstation-03 | MS17-010 security update | Pending - schedule |
| HR-Workstation-03 | Print Spooler update KB5004945 | Pending - schedule |

8 row(s)

## Q23 - Assets with BOTH a Critical and a High open finding (intersection via EXISTS)
*Set. MySQL has no INTERSECT before 8.0.31, so two EXISTS do the job.*

```sql
SELECT a.name, a.owner_dept
FROM ASSET a
WHERE EXISTS (SELECT 1 FROM v_open_exposure e WHERE e.asset_id = a.asset_id AND e.severity = 'Critical')
  AND EXISTS (SELECT 1 FROM v_open_exposure e WHERE e.asset_id = a.asset_id AND e.severity = 'High');
```
| name | owner_dept |
|---|---|
| DomainController-01 | IT Infrastructure |

1 row(s)

## Q24 - Department x severity matrix of open findings (pivot with CASE)
*Set. Conditional aggregation turns rows into columns.*

```sql
SELECT owner_dept,
       SUM(severity = 'Critical') AS critical, SUM(severity = 'High') AS high,
       SUM(severity = 'Medium')   AS medium,   SUM(severity = 'Low')  AS low
FROM v_open_exposure
GROUP BY owner_dept;
```
| owner_dept | critical | high | medium | low |
|---|---|---|---|---|
| Finance | 0 | 0 | 0 | 1 |
| HR | 0 | 2 | 0 | 0 |
| IT Infrastructure | 3 | 4 | 1 | 0 |

3 row(s)

## Q25 - SLA breaches (open longer than the severity's deadline)
*Business. Uses fn_sla_days() through the view: Critical 7d, High 30d, Medium 60d, Low 90d.*

```sql
SELECT asset_name, cve_id, severity, days_exposed, sla_days, days_exposed - sla_days AS days_overdue, patch_state
FROM v_open_exposure
WHERE sla_breached = 1
ORDER BY days_overdue DESC;
```
| asset_name | cve_id | severity | days_exposed | sla_days | days_overdue | patch_state |
|---|---|---|---|---|---|---|
| DomainController-01 | CVE-2020-1472 | Critical | 104 | 7 | 97 | Pending |
| WebServer-01 | CVE-2018-11776 | High | 118 | 30 | 88 | No patch available |
| FileServer-01 | CVE-2019-0708 | Critical | 86 | 7 | 79 | Failed |
| HR-Workstation-03 | CVE-2017-0144 | High | 86 | 30 | 56 | Pending |
| MailServer-01 | CVE-2021-26855 | Critical | 56 | 7 | 49 | Applied |
| HR-Workstation-03 | CVE-2021-34527 | High | 37 | 30 | 7 | Pending |
| DomainController-01 | CVE-2021-34527 | High | 37 | 30 | 7 | Failed |

7 row(s)

## Q26 - Patched but not verified (patch Applied, latest scan still Open)
*Business. Needs a re-scan to close the finding.*

```sql
SELECT asset_name, cve_id, severity, last_scanned
FROM v_open_exposure
WHERE patch_state = 'Applied';
```
| asset_name | cve_id | severity | last_scanned |
|---|---|---|---|
| MailServer-01 | CVE-2021-26855 | Critical | 2026-09-01 |

1 row(s)

## Q27 - Findings with no vendor patch available (need mitigation instead)
*Business. Filter on the derived patch_state column.*

```sql
SELECT asset_name, cve_id, severity, days_exposed
FROM v_open_exposure
WHERE patch_state = 'No patch available'
ORDER BY days_exposed DESC;
```
| asset_name | cve_id | severity | days_exposed |
|---|---|---|---|
| WebServer-01 | CVE-2018-11776 | High | 118 |
| Finance-Desktop-02 | CVE-2015-4000 | Low | 17 |

2 row(s)

## Q28 - Risk score per asset using the stored function fn_asset_risk()
*Business. Calls a user-defined function row by row.*

```sql
SELECT asset_id, name, owner_dept, fn_asset_risk(asset_id) AS risk_score
FROM ASSET
ORDER BY risk_score DESC;
```
| asset_id | name | owner_dept | risk_score |
|---|---|---|---|
| 8 | DomainController-01 | IT Infrastructure | 18.8 |
| 6 | HR-Workstation-03 | HR | 16.9 |
| 9 | FileServer-01 | IT Infrastructure | 15.7 |
| 10 | MailServer-01 | IT Infrastructure | 9.8 |
| 1 | WebServer-01 | IT Infrastructure | 8.1 |
| 7 | AppServer-02 | IT Infrastructure | 7.8 |
| 2 | DBServer-01 | IT Infrastructure | 7.8 |
| 11 | Finance-Desktop-02 | Finance | 3.7 |
| 4 | DevLaptop-15 | Engineering | 0.0 |
| 5 | CoreRouter-01 | Network Ops | 0.0 |
| 3 | DevLaptop-14 | Engineering | 0.0 |

11 row(s)

## Q29 - Top 3 most exposed assets
*Business. ORDER BY + LIMIT on the view.*

```sql
SELECT asset_name, owner_dept, open_findings, critical_open, risk_score
FROM v_asset_risk
ORDER BY risk_score DESC
LIMIT 3;
```
| asset_name | owner_dept | open_findings | critical_open | risk_score |
|---|---|---|---|---|
| DomainController-01 | IT Infrastructure | 2 | 1 | 18.8 |
| HR-Workstation-03 | HR | 2 | 0 | 16.9 |
| FileServer-01 | IT Infrastructure | 2 | 1 | 15.7 |

3 row(s)

## Q30 - Full report for one asset via stored procedure (DomainController-01)
*Business. CALL returns a result set from sp_asset_report().*

```sql
CALL sp_asset_report(8);
```
| cve_id | severity | cvss_score | first_detected | days_exposed | sla_days | sla | patch_state |
|---|---|---|---|---|---|---|---|
| CVE-2020-1472 | Critical | 10.0 | 2026-07-15 | 104 | 7 | BREACHED | Pending |
| CVE-2021-34527 | High | 8.8 | 2026-09-20 | 37 | 30 | BREACHED | Failed |

2 row(s)
