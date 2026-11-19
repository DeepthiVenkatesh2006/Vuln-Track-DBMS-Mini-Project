# VulnTrack: Relational Schema and DDL (updated)

Same structure as the original document: 5 tables mapped from the ER diagram, plus one audit table.
Changes are marked **[CHANGED]** / **[NEW]**. The runnable SQL lives in `sql/` (this file explains it).

## 1. Relational Schema (mapped from the ER diagram)

Each entity becomes a table. Each M:N relationship becomes its own table (a junction table) holding
foreign keys to both sides plus any relationship attributes. The 1:N relationship
(VULNERABILITY-PATCH) is absorbed as a foreign key on the "many" side (PATCH).

```
ASSET (asset_id, name, type, ip_address, owner_dept, os_version)
    PK: asset_id

VULNERABILITY (vuln_id, cve_id, description, cvss_score, severity*, published_date)
    PK: vuln_id            * severity is DERIVED from cvss_score  [CHANGED]

PATCH (patch_id, vuln_id, release_date, description)
    PK: patch_id
    FK: vuln_id -> VULNERABILITY(vuln_id)

SCAN_RESULTS (asset_id, vuln_id, scan_date, scanner_used, detection_status)
    PK: (asset_id, vuln_id, scan_date)
    FK: asset_id -> ASSET(asset_id)
    FK: vuln_id  -> VULNERABILITY(vuln_id)

PATCH_STATUS (asset_id, patch_id, applied_date, patch_status)
    PK: (asset_id, patch_id)
    FK: asset_id -> ASSET(asset_id)
    FK: patch_id -> PATCH(patch_id)

PATCH_STATUS_LOG (log_id, asset_id, patch_id, old_status, new_status, changed_at)     [NEW]
    PK: log_id             (audit table, no FKs on purpose)
```

**Why SCAN_RESULTS has a 3-part key:** the same asset can be scanned for the same vulnerability on
multiple dates, so `scan_date` is part of the key to keep scan history instead of overwriting it.
The *current* state of a finding is its newest scan row (view `v_latest_scan`).

**Normalization note [CHANGED]:** in the original, `severity` depended on `cvss_score`, which is not
a key: a transitive dependency, so the "3NF" claim was not strictly true (and the two could disagree:
EternalBlue, 8.1, was stored as "Critical"). `severity` is now a *generated column* computed from
`cvss_score` (9.0+ Critical, 7.0+ High, 4.0+ Medium, else Low), so it can never be inconsistent.
All other non-key attributes depend only on their table's full primary key, so the schema is in 3NF.

**Known simplification:** PATCH is 1:N (one patch fixes one vulnerability). Real patches (e.g. a Windows
cumulative update) can fix many CVEs, which would make it M:N. Kept 1:N to match the original ER design.

## 2. DDL (MySQL / MariaDB)  ->  `sql/vulntrack_ddl.sql`

Full, runnable text is in that file. Summary of what it creates and what changed:

| Table | Notes |
|---|---|
| ASSET | unchanged; **[NEW]** index on `owner_dept` |
| VULNERABILITY | **[CHANGED]** `severity` is `GENERATED ALWAYS AS (...) STORED`; `cvss_score` is `NOT NULL` with `CHECK 0..10`; **[NEW]** index on `severity` |
| PATCH | unchanged (`ON DELETE CASCADE` from VULNERABILITY) |
| SCAN_RESULTS | unchanged |
| PATCH_STATUS | **[NEW]** `CHECK (patch_status <> 'Applied' OR applied_date IS NOT NULL)` |
| PATCH_STATUS_LOG | **[NEW]** moved into the main DDL (it was only in the optional section) |

```sql
-- the one structural change, as it appears in the DDL:
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
    INDEX idx_vuln_severity (severity)
);
```

## 3. Supporting objects  ->  `sql/vulntrack_objects.sql`

**Views**

| View | Purpose |
|---|---|
| `v_latest_scan` | newest scan row per (asset, vulnerability) = the current state |
| `v_open_exposure` | every still-open finding with first-detected date, days exposed, SLA deadline, breached flag and patch state |
| `v_asset_risk` | per-asset open findings, critical count, SLA breaches and risk score |

**Functions:** `fn_sla_days(severity)` (Critical 7, High 30, Medium 60, Low 90 days) and `fn_asset_risk(asset_id)`
(sum of CVSS of open findings).

**Stored procedures:** `sp_register_scan` (record a scan by CVE id), `sp_set_patch_status` (insert/update a patch
state), `sp_asset_report` (one-asset findings report).

**Triggers**

| Trigger | When | What |
|---|---|---|
| `trg_ps_bi` | BEFORE INSERT on PATCH_STATUS | refuses a patch on an asset never scanned for that vulnerability; defaults `applied_date` |
| `trg_ps_bu` | BEFORE UPDATE on PATCH_STATUS | keeps `applied_date` consistent with the status |
| `trg_ps_au` | AFTER UPDATE on PATCH_STATUS | audit log (the original trigger, renamed) |
| `trg_ps_ai` | AFTER INSERT on PATCH_STATUS | audit log for new rows **[NEW, was missing]** |
| `trg_scan_bi` | BEFORE INSERT on SCAN_RESULTS | rejects scan dates in the future |

**Headline query [CHANGED]** (Critical findings open for more than 30 days). The original joined raw scan rows and
measured days from the *last scan*; it would double-count re-scans. The fixed version reads `v_open_exposure`
(latest scan only, days counted from *first detection*):

```sql
SELECT asset_name, cve_id, severity, first_detected, days_exposed, patch_state
FROM v_open_exposure
WHERE severity = 'Critical' AND days_exposed > 30
ORDER BY days_exposed DESC;
```

The other 29 queries are in `sql/vulntrack_queries.sql`, with captured output in `docs/query_outputs.md`.


## APP_USER (added for role-based access control)
`user_id` PK, `username` UNIQUE, `password_hash` (salted, never plain text), `role` ENUM('viewer','analyst','admin'), `is_active`, `created_at`, `last_login`. It is standalone (no foreign keys): it only controls who may use the web app and does not touch the vulnerability data model.
