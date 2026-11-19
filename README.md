# VulnTrack - Vulnerability & Patch Compliance Tracker
DBMS mini project. A relational database (MySQL) that records which assets have which vulnerabilities, whether a patch
exists, and whether it was applied, plus a web front-end to use it.
**Now also uses MongoDB** (polyglot persistence): MySQL holds the structured, constrained data; MongoDB holds flexible
documents - CVE advisories, raw scanner output, analyst notes.

```
vulntrack/
├── README.md
├── sql/
│   ├── vulntrack_ddl.sql       tables, constraints, indexes        (run 1st)
│   ├── vulntrack_dml.sql       sample data                         (run 2nd)
│   ├── vulntrack_objects.sql   views, functions, procedures, triggers (run 3rd)
│   └── vulntrack_queries.sql   30 demo queries
├── app/                        Flask web front-end
│   ├── app.py  auth.py  db.py  mongo_db.py  config.py  queries_file.py  requirements.txt
│   ├── setup_db.py (MySQL)   setup_mongo.py (MongoDB)
│   ├── templates/  static/
├── mongo/vulntrack_mongo_queries.js   8 mongosh demo queries
├── docker-compose.yml                 optional: run MongoDB in Docker
└── docs/
    ├── vulntrack_erd_plain.png  vulntrack_relational_schema.png
    ├── vulntrack_schema_and_ddl.md   schema explanation (updated)
    ├── CHANGES.md   what was fixed/added      query_outputs.md   captured results
    └── screenshots/
```

## Run it
Needs Python 3.9+, a running MySQL 8 (or MariaDB 10.5+) **and** a running MongoDB 6/7.

```bash
# 0. start MongoDB (pick one)
docker compose up -d                       # Docker, from the project root
#   or install MongoDB Community and start it:  sudo systemctl start mongod   (Linux)
#                                               brew services start mongodb-community   (macOS)
#                                               net start MongoDB                        (Windows, admin shell)

cd app
pip install -r requirements.txt

# 1. tell the app your MySQL login (Windows: use `set` instead of `export`)
export VT_DB_USER=root
export VT_DB_PASSWORD=your_password
# optional: export VT_MONGO_URI=mongodb://localhost:27017

# 2. build both databases
python setup_db.py        # MySQL  -> `vulntrack`        (drops and recreates, creates the 3 login users)
python setup_mongo.py     # MongoDB -> `vulntrack_docs`   (reads CVEs/scans from MySQL, so run it second)

# 3. start the web app
python app.py             # open http://127.0.0.1:5000
```

No MongoDB handy? `export VT_MONGO_MOCK=1` before steps 2-3 uses an in-memory fake (data resets when the app stops).
If MongoDB is simply down, the MySQL pages still work and Mongo-backed panels show a notice.

**SQL only (no web app):** `mysql -u root -p < sql/vulntrack_ddl.sql`, then `..._dml.sql`, then `..._objects.sql`,
then `..._queries.sql`.  **Mongo shell demo:** `mongosh --file mongo/vulntrack_mongo_queries.js`.

## Login and roles (role-based access control)
Open http://127.0.0.1:5000 and sign in. `setup_db.py` creates three accounts:

| Username | Password | Role | Can do |
|---|---|---|---|
| `viewer` | `Viewer@123` | viewer | read-only: every page except the audit log and users |
| `analyst` | `Analyst@123` | analyst | viewer + record scans, set/mark patch status, edit advisories, add own notes, audit log |
| `admin` | `Admin@123` | admin | analyst + add/edit/delete assets, vulnerabilities, patches, scan rows, delete any note, manage users |

**Change these passwords** (Account page, or Users page as admin), or set `VT_ADMIN_PASSWORD`, `VT_ANALYST_PASSWORD`,
`VT_VIEWER_PASSWORD` before `python setup_db.py`. Set `VT_SECRET` to a long random string for the session cookie.

How it is enforced (`app/auth.py`): every request is checked server-side against a role table (the buttons you cannot use are
also hidden, but hiding is only cosmetic); roles are re-read from the database on each request so a demotion or disable takes
effect immediately; passwords are salted hashes in MySQL table `APP_USER`; every POST needs a CSRF token; login is throttled
(5 failures -> 5 minute lock); the last active admin cannot be demoted, disabled or deleted; notes record the signed-in username.

## Which data lives where
| MySQL (structured, constrained) | MongoDB `vulntrack_docs` (flexible documents) |
|---|---|
| assets, vulnerabilities, patches, scan results, patch status, audit log (triggers) | `advisories` (1 per CVE: mitigations, references, affected products, tags) |
| views, stored procedures, SLA logic | `scan_reports` (raw Nessus/OpenVAS JSON - different shape per scanner) |
| | `asset_notes` (free-form analyst notes with tags) |

The two are linked by `cve_id` and `asset_id`. Cross-database features: the dashboard panel *Actively exploited & still open*
(Mongo advisories x MySQL `v_open_exposure`), and deleting a vulnerability also removes its Mongo documents.

## What's in the web app
| Page | What it does |
|---|---|
| Dashboard | KPIs, open findings by severity/department, riskiest assets, most overdue findings |
| Exposure & SLA | every open finding with its deadline (Critical 7d / High 30d / Medium 60d / Low 90d) |
| Assets · Vulnerabilities · Patches | add / edit / delete / search (severity is computed from CVSS) |
| Scans | full scan history; record a scan (calls `sp_register_scan`) |
| Patch status | track patches per asset; one-click "Mark applied" (calls `sp_set_patch_status`) |
| Query lab | shows and runs all 30 SQL queries live |
| Audit log | patch-status changes written by database triggers |
| Advisories *(MongoDB)* | search, tag filter, edit per-CVE documents; tag counts via an aggregation pipeline |
| Scan reports *(MongoDB)* | raw scanner JSON per scan, filter by asset |
| Asset page notes *(MongoDB)* | add / delete analyst notes |

Try it for the viva: on *Patch status* click **Mark applied** on a row, then open *Audit log* (trigger fired), then
record a *Resolved* scan for that asset+CVE and watch the finding disappear from *Exposure & SLA*.

## Notes
- Tested on MariaDB 10.11. Uses `CHECK` (MySQL 8.0.16+), generated columns, window functions (MySQL 8 / MariaDB 10.2+).
- Sample data is illustrative. Day counts use today's date, so numbers shift daily.
- Not suitable for production as-is: the dev server is Flask's built-in one, there is no HTTPS, and the login throttle is in memory (resets on restart).
