"""VulnTrack web front-end (Flask + PyMySQL).  Run:  python app.py  ->  http://127.0.0.1:5000"""
import json
import re
from datetime import date, datetime

import pymysql
from bson import ObjectId
from bson.errors import InvalidId
from flask import Flask, flash, g, redirect, render_template, request, url_for
from pymongo.errors import PyMongoError

import auth
import db
import mongo_db
import queries_file
from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
auth.register(app)          # login, roles, CSRF, user management


# ---------------------------------------------------------------- helpers
@app.template_filter("badge")
def badge(v):
    """Colour-coded pill for severity / status words."""
    cls = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low",
           "Open": "high", "Resolved": "ok", "False Positive": "muted",
           "Pending": "med", "Applied": "ok", "Failed": "crit",
           "No patch available": "crit", "Not started": "med"}.get(str(v), "muted")
    return f'<span class="pill {cls}">{v}</span>'


@app.template_filter("show")
def show(v):
    return "—" if v is None or v == "" else v


@app.template_global()
def row_url(endpoint, ident):
    """url_for() for the edit/delete routes, whatever their id argument is called."""
    rule = next(app.url_map.iter_rules(endpoint))
    return url_for(endpoint, **{next(iter(rule.arguments)): ident})


def db_call(fn, ok_msg=None):
    """Run a DB action; turn any MySQL error (incl. trigger SIGNALs) into a flash message."""
    try:
        r = fn()
        if ok_msg:
            flash(ok_msg, "ok")
        return r
    except pymysql.MySQLError as e:
        msg = e.args[1] if len(e.args) > 1 else str(e)
        if getattr(e, "args", [None])[0] == 1451:
            msg = "Cannot delete: other records still depend on this row."
        elif e.args[0] == 1062:
            msg = "Duplicate value: " + msg
        flash(msg, "err")
        return None


def f(name, label, type="text", required=True, options=None, value=None, placeholder=""):
    return dict(name=name, label=label, type=type, required=required,
                options=options or [], value=value, placeholder=placeholder)


def form_vals(fields):
    return {x["name"]: (request.form.get(x["name"], "").strip() or None) for x in fields}


def asset_options():
    return [(r["asset_id"], f'{r["name"]} ({r["owner_dept"] or "-"})')
            for r in db.query("SELECT asset_id,name,owner_dept FROM ASSET ORDER BY name")]


def vuln_options():
    return [(r["vuln_id"], f'{r["cve_id"]} [{r["severity"]}]')
            for r in db.query("SELECT vuln_id,cve_id,severity FROM VULNERABILITY ORDER BY cve_id")]


# ---------------------------------------------------------------- dashboard
@app.route("/")
def dashboard():
    kpi = db.one("""
        SELECT (SELECT COUNT(*) FROM ASSET)                              AS assets,
               (SELECT COUNT(*) FROM v_open_exposure)                    AS open_findings,
               (SELECT COUNT(*) FROM v_open_exposure WHERE severity='Critical') AS critical_open,
               (SELECT COALESCE(SUM(sla_breached),0) FROM v_open_exposure) AS sla_breaches,
               (SELECT COUNT(*) FROM ASSET WHERE asset_id NOT IN (SELECT asset_id FROM SCAN_RESULTS)) AS unscanned,
               (SELECT ROUND(100*SUM(patch_status='Applied')/COUNT(*),0) FROM PATCH_STATUS) AS compliance""")
    sev = {r["severity"]: r["n"] for r in db.query(
        "SELECT severity, COUNT(*) n FROM v_open_exposure GROUP BY severity")}
    sev_rows = [(s, sev.get(s, 0)) for s in ("Critical", "High", "Medium", "Low")]
    top = db.query("SELECT * FROM v_asset_risk ORDER BY risk_score DESC LIMIT 5")
    depts = db.query("""SELECT owner_dept, COUNT(*) open_findings, SUM(severity='Critical') critical,
                               SUM(sla_breached) sla_breaches
                        FROM v_open_exposure GROUP BY owner_dept ORDER BY open_findings DESC""")
    breaches = db.query("""SELECT asset_name, cve_id, severity, days_exposed, sla_days, patch_state
                           FROM v_open_exposure WHERE sla_breached=1
                           ORDER BY days_exposed - sla_days DESC LIMIT 6""")
    audit = db.query("""SELECT l.*, a.name asset FROM PATCH_STATUS_LOG l
                        LEFT JOIN ASSET a ON a.asset_id=l.asset_id ORDER BY log_id DESC LIMIT 5""")
    exploited = None            # MongoDB + MySQL together; None means MongoDB is not reachable
    try:
        cves = [a["cve_id"] for a in mongo_db.mdb().advisories.find({"exploited_in_wild": True}, {"cve_id": 1})]
        if cves:
            ph = ",".join(["%s"] * len(cves))
            exploited = db.query(f"""SELECT asset_name, cve_id, severity, days_exposed, patch_state
                                    FROM v_open_exposure WHERE cve_id IN ({ph})
                                    ORDER BY cvss_score DESC, days_exposed DESC LIMIT 6""", cves)
        else:
            exploited = []
    except PyMongoError:
        pass
    return render_template("dashboard.html", kpi=kpi, sev_rows=sev_rows, top=top,
                           depts=depts, breaches=breaches, audit=audit, exploited=exploited,
                           sev_max=max([n for _, n in sev_rows] + [1]))


# ---------------------------------------------------------------- assets
ASSET_TYPES = ["Server", "Laptop", "Desktop", "Router", "Switch", "Firewall", "Other"]


def asset_fields(v=None):
    v = v or {}
    return [f("name", "Name", value=v.get("name")),
            f("type", "Type", "select", options=[(t, t) for t in ASSET_TYPES], value=v.get("type")),
            f("ip_address", "IP address", required=False, value=v.get("ip_address"), placeholder="192.168.1.50"),
            f("owner_dept", "Owner department", required=False, value=v.get("owner_dept")),
            f("os_version", "OS version", required=False, value=v.get("os_version"))]


@app.route("/assets", methods=["GET", "POST"])
def assets():
    fields = asset_fields()
    if request.method == "POST":
        v = form_vals(fields)
        db_call(lambda: db.execute(
            "INSERT INTO ASSET (name,type,ip_address,owner_dept,os_version) VALUES (%s,%s,%s,%s,%s)",
            (v["name"], v["type"], v["ip_address"], v["owner_dept"], v["os_version"])), "Asset added.")
        return redirect(url_for("assets"))
    q = request.args.get("q", "").strip()
    rows = db.query("""SELECT r.asset_id, r.asset_name, r.type, a.ip_address, r.owner_dept, a.os_version,
                              r.open_findings, r.critical_open, r.risk_score
                       FROM v_asset_risk r JOIN ASSET a ON a.asset_id=r.asset_id
                       WHERE %s='' OR r.asset_name LIKE %s OR r.owner_dept LIKE %s OR a.ip_address LIKE %s
                       ORDER BY r.risk_score DESC, r.asset_name""", (q, f"%{q}%", f"%{q}%", f"%{q}%"))
    cols = [("asset_name", "Name", "link:asset"), ("type", "Type"), ("ip_address", "IP"), ("owner_dept", "Dept"),
            ("os_version", "OS"), ("open_findings", "Open"), ("critical_open", "Critical"), ("risk_score", "Risk")]
    return render_template("list.html", title="Assets", subtitle="Machines and devices being tracked.",
                           cols=cols, rows=rows, fields=fields, add_label="Add asset", q=q,
                           edit="asset_edit", delete="asset_delete", pk="asset_id")


@app.route("/assets/<int:aid>")
def asset(aid):
    a = db.one("SELECT * FROM ASSET WHERE asset_id=%s", (aid,))
    if not a:
        return redirect(url_for("assets"))
    cols, rows = db.run_any(f"CALL sp_asset_report({int(aid)})")
    history = db.query("""SELECT v.cve_id, sr.scan_date, sr.scanner_used, sr.detection_status
                          FROM SCAN_RESULTS sr JOIN VULNERABILITY v ON v.vuln_id=sr.vuln_id
                          WHERE sr.asset_id=%s ORDER BY sr.scan_date DESC, v.cve_id""", (aid,))
    patches = db.query("""SELECT v.cve_id, p.description patch, ps.patch_status, ps.applied_date
                          FROM PATCH_STATUS ps JOIN PATCH p ON p.patch_id=ps.patch_id
                          JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id WHERE ps.asset_id=%s""", (aid,))
    risk = db.one("SELECT fn_asset_risk(%s) AS r", (aid,))["r"]
    try:
        notes = list(mongo_db.mdb().asset_notes.find({"asset_id": aid}).sort("created_at", -1))
    except PyMongoError:
        notes = None            # MongoDB down: the rest of the page still works
    return render_template("asset.html", a=a, findings=rows, history=history, patches=patches, risk=risk, notes=notes)


@app.post("/assets/<int:aid>/notes")
def note_add(aid):
    text = request.form.get("text", "").strip()
    if text:
        tags = [t.strip().lower() for t in request.form.get("tags", "").split(",") if t.strip()]
        try:
            mongo_db.mdb().asset_notes.insert_one({"asset_id": aid, "author": g.user["username"],
                                                   "text": text, "tags": tags, "created_at": datetime.utcnow()})
            flash("Note saved in MongoDB.", "ok")
        except PyMongoError as e:
            flash(f"MongoDB error: {e}", "err")
    return redirect(url_for("asset", aid=aid))


@app.post("/notes/<nid>/delete")
def note_delete(nid):
    aid = request.form.get("asset_id", type=int)
    try:
        note = mongo_db.mdb().asset_notes.find_one({"_id": ObjectId(nid)})
        if note and not (auth.can("admin") or note.get("author") == g.user["username"]):
            flash("Analysts can only delete their own notes.", "err")      # admins can delete any note
            return redirect(url_for("asset", aid=aid) if aid else url_for("assets"))
        mongo_db.mdb().asset_notes.delete_one({"_id": ObjectId(nid)})
        flash("Note deleted.", "ok")
    except (PyMongoError, InvalidId) as e:
        flash(f"Could not delete note: {e}", "err")
    return redirect(url_for("asset", aid=aid) if aid else url_for("assets"))


@app.route("/assets/<int:aid>/edit", methods=["GET", "POST"])
def asset_edit(aid):
    a = db.one("SELECT * FROM ASSET WHERE asset_id=%s", (aid,))
    fields = asset_fields(a)
    if request.method == "POST":
        v = form_vals(fields)
        if db_call(lambda: db.execute(
                "UPDATE ASSET SET name=%s,type=%s,ip_address=%s,owner_dept=%s,os_version=%s WHERE asset_id=%s",
                (v["name"], v["type"], v["ip_address"], v["owner_dept"], v["os_version"], aid)), "Asset updated.") is not None:
            return redirect(url_for("assets"))
        fields = asset_fields({**a, **v})
    return render_template("form.html", title=f"Edit asset #{aid}", fields=fields, back=url_for("assets"))


@app.post("/assets/<int:aid>/delete")
def asset_delete(aid):
    db_call(lambda: db.execute("DELETE FROM ASSET WHERE asset_id=%s", (aid,)),
            "Asset deleted (its scans and patch rows were removed with it).")
    return redirect(url_for("assets"))


# ---------------------------------------------------------------- vulnerabilities
def vuln_fields(v=None):
    v = v or {}
    return [f("cve_id", "CVE id", value=v.get("cve_id"), placeholder="CVE-2024-12345"),
            f("cvss_score", "CVSS score (0-10)", "number", value=v.get("cvss_score")),
            f("published_date", "Published date", "date", required=False, value=v.get("published_date")),
            f("description", "Description", "textarea", required=False, value=v.get("description"))]


@app.route("/vulnerabilities", methods=["GET", "POST"])
def vulns():
    fields = vuln_fields()
    if request.method == "POST":
        v = form_vals(fields)
        db_call(lambda: db.execute(
            "INSERT INTO VULNERABILITY (cve_id,cvss_score,published_date,description) VALUES (%s,%s,%s,%s)",
            (v["cve_id"], v["cvss_score"], v["published_date"], v["description"])),
            "Vulnerability added - severity was computed from the CVSS score.")
        return redirect(url_for("vulns"))
    sev = request.args.get("severity", "")
    rows = db.query("""SELECT v.vuln_id, v.cve_id, v.severity, v.cvss_score, v.published_date, v.description,
                              (SELECT COUNT(*) FROM PATCH p WHERE p.vuln_id=v.vuln_id) AS patches,
                              (SELECT COUNT(*) FROM v_open_exposure e WHERE e.vuln_id=v.vuln_id) AS open_on
                       FROM VULNERABILITY v WHERE %s='' OR v.severity=%s
                       ORDER BY v.cvss_score DESC""", (sev, sev))
    cols = [("cve_id", "CVE"), ("severity", "Severity", "badge"), ("cvss_score", "CVSS"),
            ("published_date", "Published"), ("description", "Description"),
            ("patches", "Patches"), ("open_on", "Open on assets")]
    return render_template("list.html", title="Vulnerabilities", cols=cols, rows=rows, fields=fields,
                           subtitle="Catalogue of known CVEs. Severity is derived from the CVSS score (Critical ≥ 9, High ≥ 7, Medium ≥ 4).",
                           add_label="Add vulnerability", sev_filter=sev,
                           edit="vuln_edit", delete="vuln_delete", pk="vuln_id")


@app.route("/vulnerabilities/<int:vid>/edit", methods=["GET", "POST"])
def vuln_edit(vid):
    row = db.one("SELECT * FROM VULNERABILITY WHERE vuln_id=%s", (vid,))
    fields = vuln_fields(row)
    if request.method == "POST":
        v = form_vals(fields)
        if db_call(lambda: db.execute(
                "UPDATE VULNERABILITY SET cve_id=%s,cvss_score=%s,published_date=%s,description=%s WHERE vuln_id=%s",
                (v["cve_id"], v["cvss_score"], v["published_date"], v["description"], vid)), "Vulnerability updated.") is not None:
            return redirect(url_for("vulns"))
        fields = vuln_fields({**row, **v})
    return render_template("form.html", title=f"Edit {row['cve_id']}", fields=fields, back=url_for("vulns"))


@app.post("/vulnerabilities/<int:vid>/delete")
def vuln_delete(vid):
    row = db.one("SELECT cve_id FROM VULNERABILITY WHERE vuln_id=%s", (vid,))
    if db_call(lambda: db.execute("DELETE FROM VULNERABILITY WHERE vuln_id=%s", (vid,)),
               "Vulnerability deleted (with its patches, scans and patch rows).") is not None and row:
        try:        # keep the two databases consistent: remove the matching MongoDB documents too
            mongo_db.mdb().advisories.delete_one({"cve_id": row["cve_id"]})
            mongo_db.mdb().scan_reports.delete_many({"cve_id": row["cve_id"]})
        except PyMongoError:
            pass
    return redirect(url_for("vulns"))


# ---------------------------------------------------------------- patches
def patch_fields(v=None):
    v = v or {}
    return [f("vuln_id", "Fixes vulnerability", "select", options=vuln_options(), value=v.get("vuln_id")),
            f("release_date", "Release date", "date", required=False, value=v.get("release_date")),
            f("description", "Description", value=v.get("description"), placeholder="KB number / version upgrade")]


@app.route("/patches", methods=["GET", "POST"])
def patches():
    fields = patch_fields()
    if request.method == "POST":
        v = form_vals(fields)
        db_call(lambda: db.execute("INSERT INTO PATCH (vuln_id,release_date,description) VALUES (%s,%s,%s)",
                                   (v["vuln_id"], v["release_date"], v["description"])), "Patch added.")
        return redirect(url_for("patches"))
    rows = db.query("""SELECT p.patch_id, v.cve_id, v.severity, p.description, p.release_date,
                              (SELECT COUNT(*) FROM PATCH_STATUS ps WHERE ps.patch_id=p.patch_id) AS tracked_on,
                              (SELECT COUNT(*) FROM PATCH_STATUS ps WHERE ps.patch_id=p.patch_id
                                  AND ps.patch_status='Applied') AS applied_on
                       FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id ORDER BY v.cvss_score DESC""")
    cols = [("cve_id", "Fixes"), ("severity", "Severity", "badge"), ("description", "Patch"),
            ("release_date", "Released"), ("tracked_on", "Tracked on assets"), ("applied_on", "Applied")]
    return render_template("list.html", title="Patches", cols=cols, rows=rows, fields=fields,
                           subtitle="Fixes available for each vulnerability (one vulnerability can have several).",
                           add_label="Add patch", edit="patch_edit", delete="patch_delete", pk="patch_id")


@app.route("/patches/<int:pid>/edit", methods=["GET", "POST"])
def patch_edit(pid):
    row = db.one("SELECT * FROM PATCH WHERE patch_id=%s", (pid,))
    fields = patch_fields(row)
    if request.method == "POST":
        v = form_vals(fields)
        if db_call(lambda: db.execute("UPDATE PATCH SET vuln_id=%s,release_date=%s,description=%s WHERE patch_id=%s",
                                      (v["vuln_id"], v["release_date"], v["description"], pid)), "Patch updated.") is not None:
            return redirect(url_for("patches"))
        fields = patch_fields({**row, **v})
    return render_template("form.html", title=f"Edit patch #{pid}", fields=fields, back=url_for("patches"))


@app.post("/patches/<int:pid>/delete")
def patch_delete(pid):
    db_call(lambda: db.execute("DELETE FROM PATCH WHERE patch_id=%s", (pid,)), "Patch deleted.")
    return redirect(url_for("patches"))


# ---------------------------------------------------------------- scans
@app.route("/scans", methods=["GET", "POST"])
def scans():
    fields = [f("asset_id", "Asset", "select", options=asset_options()),
              f("vuln_id", "Vulnerability", "select", options=vuln_options()),
              f("scan_date", "Scan date", "date", value=date.today().isoformat()),
              f("scanner_used", "Scanner", "select", options=[(s, s) for s in ("Nessus", "OpenVAS", "Qualys", "Nmap", "Manual")]),
              f("detection_status", "Result", "select", options=[(s, s) for s in ("Open", "Resolved", "False Positive")])]
    if request.method == "POST":
        v = form_vals(fields)

        def go():
            cve = db.one("SELECT cve_id FROM VULNERABILITY WHERE vuln_id=%s", (v["vuln_id"],))["cve_id"]
            db.execute("CALL sp_register_scan(%s,%s,%s,%s,%s)",
                       (v["asset_id"], cve, v["scanner_used"], v["scan_date"], v["detection_status"]))
        db_call(go, "Scan recorded (stored procedure sp_register_scan).")
        return redirect(url_for("scans"))
    status = request.args.get("status", "")
    aid = request.args.get("asset", "")
    rows = db.query("""SELECT a.name asset, a.asset_id, v.cve_id, v.vuln_id, v.severity, sr.scan_date,
                              sr.scanner_used, sr.detection_status
                       FROM SCAN_RESULTS sr JOIN ASSET a ON a.asset_id=sr.asset_id
                       JOIN VULNERABILITY v ON v.vuln_id=sr.vuln_id
                       WHERE (%s='' OR sr.detection_status=%s) AND (%s='' OR sr.asset_id=%s)
                       ORDER BY sr.scan_date DESC, a.name""", (status, status, aid, aid or 0))
    cols = [("asset", "Asset"), ("cve_id", "CVE"), ("severity", "Severity", "badge"), ("scan_date", "Scan date"),
            ("scanner_used", "Scanner"), ("detection_status", "Result", "badge")]
    return render_template("list.html", title="Scan results",
                           subtitle="Full scan history. A finding is closed by recording a later 'Resolved' scan - old rows are kept as history.",
                           cols=cols, rows=rows, fields=fields, add_label="Record scan", add_role="analyst",
                           status_filter=status, asset_filter=aid, asset_opts=asset_options(),
                           delete="scan_delete", composite=["asset_id", "vuln_id", "scan_date"])


@app.post("/scans/delete")
def scan_delete():
    db_call(lambda: db.execute("DELETE FROM SCAN_RESULTS WHERE asset_id=%s AND vuln_id=%s AND scan_date=%s",
                               (request.form["asset_id"], request.form["vuln_id"], request.form["scan_date"])),
            "Scan row deleted.")
    return redirect(url_for("scans"))


# ---------------------------------------------------------------- patch status
@app.route("/patch-status", methods=["GET", "POST"])
def patch_status():
    patch_opts = [(r["patch_id"], f'{r["cve_id"]} - {r["description"]}') for r in db.query(
        "SELECT p.patch_id,v.cve_id,p.description FROM PATCH p JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id ORDER BY v.cve_id")]
    fields = [f("asset_id", "Asset", "select", options=asset_options()),
              f("patch_id", "Patch", "select", options=patch_opts),
              f("patch_status", "Status", "select", options=[(s, s) for s in ("Pending", "Applied", "Failed")]),
              f("applied_date", "Applied date (blank = today if Applied)", "date", required=False)]
    if request.method == "POST":
        v = form_vals(fields)
        db_call(lambda: db.execute("CALL sp_set_patch_status(%s,%s,%s,%s)",
                                   (v["asset_id"], v["patch_id"], v["patch_status"], v["applied_date"])),
                "Patch status saved (change logged by trigger).")
        return redirect(url_for("patch_status"))
    rows = db.query("""SELECT a.name asset, a.asset_id, ps.patch_id, v.cve_id, v.severity, p.description patch,
                              ps.patch_status, ps.applied_date
                       FROM PATCH_STATUS ps JOIN ASSET a ON a.asset_id=ps.asset_id
                       JOIN PATCH p ON p.patch_id=ps.patch_id JOIN VULNERABILITY v ON v.vuln_id=p.vuln_id
                       ORDER BY FIELD(ps.patch_status,'Failed','Pending','Applied'), v.cvss_score DESC""")
    cols = [("asset", "Asset"), ("cve_id", "CVE"), ("severity", "Severity", "badge"), ("patch", "Patch"),
            ("patch_status", "Status", "badge"), ("applied_date", "Applied on")]
    return render_template("list.html", title="Patch status",
                           subtitle="Has each asset actually applied the patch? Saving a change writes an entry to the audit log.",
                           cols=cols, rows=rows, fields=fields, add_label="Set patch status", add_role="analyst",
                           delete="ps_delete", composite=["asset_id", "patch_id"], apply_action="ps_apply")


@app.post("/patch-status/apply")
def ps_apply():
    db_call(lambda: db.execute("CALL sp_set_patch_status(%s,%s,'Applied',CURDATE())",
                               (request.form["asset_id"], request.form["patch_id"])), "Marked as applied today.")
    return redirect(url_for("patch_status"))


@app.post("/patch-status/delete")
def ps_delete():
    db_call(lambda: db.execute("DELETE FROM PATCH_STATUS WHERE asset_id=%s AND patch_id=%s",
                               (request.form["asset_id"], request.form["patch_id"])), "Row deleted.")
    return redirect(url_for("patch_status"))


# ---------------------------------------------------------------- exposure / SLA
@app.route("/exposure")
def exposure():
    only = request.args.get("breached") == "1"
    rows = db.query("""SELECT * FROM v_open_exposure WHERE (%s=0 OR sla_breached=1)
                       ORDER BY sla_breached DESC, cvss_score DESC""", (1 if only else 0,))
    return render_template("exposure.html", rows=rows, only=only)


# ---------------------------------------------------------------- query lab
@app.route("/queries")
def queries():
    qs = queries_file.load()
    groups = {}
    for q in qs:
        groups.setdefault(q["category"], []).append(q)
    return render_template("queries.html", groups=groups, total=len(qs))


@app.route("/queries/<qid>")
def query_run(qid):
    q = next((x for x in queries_file.load() if x["id"] == qid), None)
    if not q:
        return redirect(url_for("queries"))
    cols, rows, err = [], [], None
    try:
        cols, rows = db.run_any(q["sql"])
    except pymysql.MySQLError as e:
        err = str(e)
    allq = queries_file.load()
    idx = allq.index(q)
    return render_template("query_run.html", q=q, cols=cols, rows=rows, err=err,
                           prev=allq[idx - 1] if idx else None, nxt=allq[idx + 1] if idx + 1 < len(allq) else None)


# ---------------------------------------------------------------- MongoDB: advisories
def lines(text):
    return [x.strip() for x in (text or "").replace("\r", "").split("\n") if x.strip()]


@app.route("/advisories")
def advisories():
    q = request.args.get("q", "").strip()
    tag = request.args.get("tag", "").strip()
    flt = {}
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        flt["$or"] = [{"cve_id": rx}, {"title": rx}, {"summary": rx}]
    if tag:
        flt["tags"] = tag
    docs = list(mongo_db.mdb().advisories.find(flt).sort("cve_id", 1))
    top_tags = list(mongo_db.mdb().advisories.aggregate([      # MongoDB aggregation pipeline
        {"$unwind": "$tags"}, {"$group": {"_id": "$tags", "n": {"$sum": 1}}},
        {"$sort": {"n": -1, "_id": 1}}, {"$limit": 12}]))
    meta = {r["cve_id"]: r for r in db.query(
        """SELECT v.cve_id, v.severity, v.cvss_score,
                  (SELECT COUNT(*) FROM v_open_exposure e WHERE e.vuln_id=v.vuln_id) AS open_on FROM VULNERABILITY v""")}
    return render_template("advisories.html", docs=docs, meta=meta, q=q, tag=tag, top_tags=top_tags)


@app.route("/advisories/<cve>", methods=["GET", "POST"])
def advisory(cve):
    v = db.one("SELECT * FROM VULNERABILITY WHERE cve_id=%s", (cve,))
    if not v:
        flash("Unknown CVE - add it under Vulnerabilities first.", "err")
        return redirect(url_for("advisories"))
    col = mongo_db.mdb().advisories
    if request.method == "POST":
        fm = request.form
        col.update_one({"cve_id": cve}, {"$set": {
            "title": fm.get("title", "").strip() or cve, "cwe": fm.get("cwe", "").strip() or None,
            "attack_vector": fm.get("attack_vector", "").strip() or None,
            "exploited_in_wild": fm.get("exploited_in_wild") == "on",
            "summary": fm.get("summary", "").strip(), "mitigations": lines(fm.get("mitigations")),
            "references": lines(fm.get("references")),
            "tags": [t.strip().lower() for t in fm.get("tags", "").split(",") if t.strip()],
            "updated_at": datetime.utcnow(), "updated_by": g.user["username"]}}, upsert=True)
        flash("Advisory saved in MongoDB.", "ok")
        return redirect(url_for("advisory", cve=cve))
    doc = col.find_one({"cve_id": cve}) or {"cve_id": cve, "title": cve, "tags": [], "mitigations": [], "references": []}
    affected = db.query("""SELECT asset_name, owner_dept, days_exposed, sla_breached, patch_state
                           FROM v_open_exposure WHERE cve_id=%s ORDER BY days_exposed DESC""", (cve,))
    reports = list(mongo_db.mdb().scan_reports.find({"cve_id": cve}).sort("scan_date", -1))
    raw = json.dumps({k: val for k, val in doc.items() if k != "_id"}, indent=2, default=str)
    return render_template("advisory.html", v=v, d=doc, affected=affected, reports=reports, raw=raw)


# ---------------------------------------------------------------- MongoDB: raw scan reports
@app.route("/scan-reports")
def scan_reports():
    aid = request.args.get("asset", type=int)
    flt = {"asset_id": aid} if aid else {}
    docs = list(mongo_db.mdb().scan_reports.find(flt).sort("scan_date", -1))
    for d in docs:
        d["raw_json"] = json.dumps(d.get("raw", {}), indent=2, default=str)
    return render_template("scan_reports.html", docs=docs, asset_filter=aid, asset_opts=asset_options())


# ---------------------------------------------------------------- audit log
@app.route("/audit")
def audit():
    rows = db.query("""SELECT l.log_id, l.changed_at, COALESCE(a.name, CONCAT('asset #', l.asset_id)) asset,
                              l.patch_id, l.old_status, l.new_status
                       FROM PATCH_STATUS_LOG l LEFT JOIN ASSET a ON a.asset_id=l.asset_id ORDER BY l.log_id DESC""")
    return render_template("audit.html", rows=rows)


@app.errorhandler(PyMongoError)
def mongo_down(e):
    return render_template("form.html", title="MongoDB error", fields=[], back=url_for("dashboard"),
                           error=f"{e}. Is MongoDB running, and did you run  python setup_mongo.py ?  "
                                 f"(no MongoDB? set VT_MONGO_MOCK=1 for an in-memory demo)"), 500


@app.errorhandler(pymysql.MySQLError)
def db_down(e):
    return render_template("form.html", title="Database error", fields=[], back=url_for("dashboard"),
                           error=f"{e}. Did you run  python setup_db.py  and set VT_DB_USER / VT_DB_PASSWORD?"), 500


if __name__ == "__main__":
    app.run(debug=True)
