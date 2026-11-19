"""Role-based access control: login/logout, CSRF protection, per-route permission checks, user management.

Roles (each includes everything below it):
  viewer   read-only: dashboard, exposure, assets, vulnerabilities, patches, scans, patch status, advisories, queries
  analyst  + record scans, set/mark patch status, edit advisories (MongoDB), add notes, view the audit log
  admin    + add/edit/delete assets, vulnerabilities, patches, scan rows; delete notes; manage users
"""
import re
import secrets
import time
from urllib.parse import urlparse

import pymysql
from flask import abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import db

LEVEL = {"viewer": 1, "analyst": 2, "admin": 3}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PW = 8

# endpoint -> minimum role. Anything not listed: GET needs viewer, any other method needs admin (safe default).
ADMIN_ALWAYS = {"asset_edit", "vuln_edit", "patch_edit", "users", "user_add", "user_role", "user_active",
                "user_password", "user_delete"}
ANALYST_ALWAYS = {"audit"}
ANALYST_WRITE = {"scans", "patch_status", "ps_apply", "advisory", "note_add", "note_delete"}
LOGIN_ONLY = {"account", "logout"}          # any signed-in user
PUBLIC = {"login", "static"}

# brute-force throttle: (ip, username) -> [failures, locked_until]
_fails = {}
MAX_FAILS, LOCK_SECONDS = 5, 300
_DUMMY_HASH = generate_password_hash("dummy-password")


def required_role(endpoint, method):
    if endpoint in LOGIN_ONLY:
        return "viewer"
    if endpoint in ADMIN_ALWAYS:
        return "admin"
    if endpoint in ANALYST_ALWAYS:
        return "analyst"
    if method in ("GET", "HEAD"):
        return "viewer"
    return "analyst" if endpoint in ANALYST_WRITE else "admin"


def can(role):
    return bool(g.get("user")) and LEVEL[g.user["role"]] >= LEVEL[role]


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def safe_next(target):
    """Only allow redirects to a path on this site."""
    if target and target.startswith("/") and not target.startswith("//") and not urlparse(target).netloc:
        return target
    return url_for("dashboard")


def admin_count(excluding=None):
    r = db.one("SELECT COUNT(*) n FROM APP_USER WHERE role='admin' AND is_active=1 AND user_id<>%s", (excluding or 0,))
    return r["n"]


def register(app):
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    app.add_template_global(can, "can")
    app.add_template_global(lambda: g.get("user"), "current_user")

    @app.template_global()
    def csrf_input():
        from markupsafe import Markup
        return Markup(f'<input type="hidden" name="_csrf" value="{csrf_token()}">')

    @app.before_request
    def gate():
        ep = request.endpoint
        g.user = None
        if ep is None or ep == "static":
            return
        uid = session.get("uid")
        if uid:                                         # re-read every request so role changes apply at once
            u = db.one("SELECT user_id, username, role, is_active FROM APP_USER WHERE user_id=%s", (uid,))
            if u and u["is_active"]:
                g.user = u
            else:
                session.clear()
        if request.method == "POST":                    # CSRF: every POST must carry the session's token
            sent, want = request.form.get("_csrf", ""), session.get("csrf", "")
            if not want or not secrets.compare_digest(sent, want):
                session.pop("csrf", None)
                flash("Your session expired or the form was invalid. Please try again.", "err")
                return redirect(request.referrer or url_for("login")) if g.user else redirect(url_for("login"))
        if ep in PUBLIC:
            return
        if not g.user:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        need = required_role(ep, request.method)
        if LEVEL[g.user["role"]] < LEVEL[need]:
            abort(403, description=f"Your role ({g.user['role']}) cannot do this. {need.capitalize()} access is required.")

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("form.html", title="Access denied", fields=[], back=url_for("dashboard"),
                               error=e.description), 403

    # ------------------------------------------------------------ login / logout / own password
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            name = request.form.get("username", "").strip()
            pw = request.form.get("password", "")
            key = (request.remote_addr, name.lower())
            count, until = _fails.get(key, [0, 0])
            if until > time.time():
                flash(f"Too many failed attempts. Try again in {int(until - time.time()) // 60 + 1} minute(s).", "err")
                return render_template("login.html"), 429
            u = db.one("SELECT * FROM APP_USER WHERE username=%s", (name,))
            ok = check_password_hash(u["password_hash"] if u else _DUMMY_HASH, pw) and u and u["is_active"]
            if ok:
                _fails.pop(key, None)
                nxt = request.args.get("next")
                session.clear()                         # new session on login (prevents session fixation)
                session["uid"] = u["user_id"]
                db.execute("UPDATE APP_USER SET last_login=NOW() WHERE user_id=%s", (u["user_id"],))
                flash(f"Signed in as {u['username']} ({u['role']}).", "ok")
                return redirect(safe_next(nxt))
            count += 1
            _fails[key] = [count, time.time() + LOCK_SECONDS if count >= MAX_FAILS else 0]
            flash("Invalid username or password.", "err")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        flash("Signed out.", "ok")
        return redirect(url_for("login"))

    @app.route("/account", methods=["GET", "POST"])
    def account():
        if request.method == "POST":
            cur, new, again = (request.form.get(k, "") for k in ("current", "new", "again"))
            row = db.one("SELECT password_hash FROM APP_USER WHERE user_id=%s", (g.user["user_id"],))
            if not check_password_hash(row["password_hash"], cur):
                flash("Current password is wrong.", "err")
            elif len(new) < MIN_PW:
                flash(f"New password must be at least {MIN_PW} characters.", "err")
            elif new != again:
                flash("The two new passwords do not match.", "err")
            else:
                db.execute("UPDATE APP_USER SET password_hash=%s WHERE user_id=%s",
                           (generate_password_hash(new), g.user["user_id"]))
                flash("Password changed.", "ok")
                return redirect(url_for("account"))
        return render_template("account.html")

    # ------------------------------------------------------------ user management (admin)
    @app.route("/users")
    def users():
        rows = db.query("SELECT user_id, username, role, is_active, created_at, last_login FROM APP_USER ORDER BY username")
        return render_template("users.html", rows=rows, roles=list(LEVEL))

    @app.post("/users/add")
    def user_add():
        name, pw, role = (request.form.get(k, "").strip() for k in ("username", "password", "role"))
        if not USERNAME_RE.match(name):
            flash("Username must be 3-32 characters: letters, digits, dot, dash, underscore.", "err")
        elif len(pw) < MIN_PW:
            flash(f"Password must be at least {MIN_PW} characters.", "err")
        elif role not in LEVEL:
            flash("Unknown role.", "err")
        else:
            try:
                db.execute("INSERT INTO APP_USER (username,password_hash,role) VALUES (%s,%s,%s)",
                           (name, generate_password_hash(pw), role))
                flash(f"User {name} created as {role}.", "ok")
            except pymysql.err.IntegrityError:
                flash("That username already exists.", "err")
        return redirect(url_for("users"))

    def target(uid):
        u = db.one("SELECT * FROM APP_USER WHERE user_id=%s", (uid,))
        if not u:
            abort(404)
        return u

    @app.post("/users/<int:uid>/role")
    def user_role(uid):
        u, role = target(uid), request.form.get("role", "")
        if role not in LEVEL:
            flash("Unknown role.", "err")
        elif u["role"] == "admin" and role != "admin" and u["is_active"] and admin_count(uid) == 0:
            flash("You cannot demote the last active admin.", "err")
        else:
            db.execute("UPDATE APP_USER SET role=%s WHERE user_id=%s", (role, uid))
            flash(f"{u['username']} is now {role}.", "ok")
        return redirect(url_for("users"))

    @app.post("/users/<int:uid>/active")
    def user_active(uid):
        u = target(uid)
        if u["is_active"] and u["role"] == "admin" and admin_count(uid) == 0:
            flash("You cannot deactivate the last active admin.", "err")
        else:
            db.execute("UPDATE APP_USER SET is_active=%s WHERE user_id=%s", (0 if u["is_active"] else 1, uid))
            flash(f"{u['username']} {'deactivated' if u['is_active'] else 'activated'}.", "ok")
        return redirect(url_for("users"))

    @app.post("/users/<int:uid>/password")
    def user_password(uid):
        u, pw = target(uid), request.form.get("password", "")
        if len(pw) < MIN_PW:
            flash(f"Password must be at least {MIN_PW} characters.", "err")
        else:
            db.execute("UPDATE APP_USER SET password_hash=%s WHERE user_id=%s", (generate_password_hash(pw), uid))
            flash(f"Password reset for {u['username']}.", "ok")
        return redirect(url_for("users"))

    @app.post("/users/<int:uid>/delete")
    def user_delete(uid):
        u = target(uid)
        if uid == g.user["user_id"]:
            flash("You cannot delete your own account.", "err")
        elif u["role"] == "admin" and u["is_active"] and admin_count(uid) == 0:
            flash("You cannot delete the last active admin.", "err")
        else:
            db.execute("DELETE FROM APP_USER WHERE user_id=%s", (uid,))
            flash(f"User {u['username']} deleted.", "ok")
        return redirect(url_for("users"))
