# What was fixed / added (vs. the original zip)

## Bugs and design problems fixed
| # | Problem in the original | Fix |
|---|---|---|
| 1 | EternalBlue (CVSS 8.1) stored as "Critical"; severity and score could disagree | `severity` is now a generated column derived from `cvss_score` |
| 2 | "3NF" claim was false (severity depended on cvss_score) | derived column removes the transitive dependency; doc explains it |
| 3 | Headline query comment said only Zerologon would show; actually every old scan did | rewritten on `v_open_exposure`; correct under today's date |
| 4 | `days_exposed` counted from the last scan; re-scans would duplicate rows | latest scan per asset+CVE only; days counted from first detection |
| 5 | Fixed findings stayed `Open` forever (Log4Shell patched but scan still Open) | sample data now has later `Resolved` re-scan rows; `sp_register_scan` records them |
| 6 | Patch could be tracked on an asset never scanned for that CVE | `trg_ps_bi` trigger blocks it |
| 7 | Audit trigger only on UPDATE; log table lived in an "optional" section | INSERT trigger added; `PATCH_STATUS_LOG` is in the main DDL |
| 8 | `Applied` rows could have no date | CHECK constraint + trigger default |
| 9 | Unrealistic sample data (Zerologon on an HR PC, BlueKeep on a router) | moved to a domain controller / Windows file server; router stays unscanned |
| 10 | ER diagram: overlapping ovals, clipped attributes | redrawn cleanly; derived attribute shown dashed |
| 11 | Relational diagram: arrow crossed another table | redrawn; every FK arrow is straight and labelled |

## Added
- Sample data grown from 7 assets / 7 CVEs to 11 assets / 13 CVEs / 21 scan rows / 13 patch-status rows
- 3 views, 2 functions, 3 stored procedures, 5 triggers (`sql/vulntrack_objects.sql`)
- 30 queries: basic, joins, aggregates, subqueries, window functions, set operations, business (`sql/vulntrack_queries.sql`)
- Flask web front-end (`app/`): dashboard, SLA/exposure view, full CRUD for assets / vulnerabilities / patches, scan recording,
  patch tracking, audit log, and a "Query lab" that runs all 30 queries live
- One-command database setup (`app/setup_db.py`)
- Screenshots and captured query output (`docs/`)

## Deliberately left as it was
- The 5-table structure and every original column name (only `severity` became derived)
- PATCH stays 1 vulnerability : N patches (simplification, noted in the schema doc)


## MongoDB layer (added)
- Second database: MongoDB `vulntrack_docs` with collections `advisories`, `scan_reports`, `asset_notes` (`app/mongo_db.py`, `app/setup_mongo.py`)
- Web pages: Advisories (list/search/tag filter/edit), Scan reports, analyst notes on the asset page, dashboard panel joining Mongo and MySQL
- Deleting a vulnerability in MySQL also removes its advisory and scan reports in MongoDB
- App degrades gracefully if MongoDB is down; `VT_MONGO_MOCK=1` runs an in-memory fake for demos
- `mongo/vulntrack_mongo_queries.js` (8 mongosh queries), `docker-compose.yml` for MongoDB


## Role-based access control (added)
- New table `APP_USER` (salted password hashes, role ENUM viewer/analyst/admin, active flag, last login) in `sql/vulntrack_ddl.sql`; default users seeded by `setup_db.py`
- `app/auth.py`: login/logout, per-route role checks, CSRF tokens on all POST forms, login throttling, safe `next` redirects, own-password change
- Admin Users page: add users, change role, enable/disable, reset password, delete; last-admin protection
- Templates hide actions the current role cannot perform; the server enforces the same rules (403 otherwise)
- Notes now store the signed-in user as author; analysts can delete only their own notes, admins any
