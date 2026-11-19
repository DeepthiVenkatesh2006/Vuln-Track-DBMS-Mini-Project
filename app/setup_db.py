"""One-shot database builder:  python setup_db.py
Runs ddl -> dml -> objects from ../sql, understanding the DELIMITER lines that only the
mysql command-line client normally handles. Wipes and recreates the `vulntrack` database."""
import os
import sys
from pathlib import Path
import pymysql
from werkzeug.security import generate_password_hash
from config import DB

SQL = Path(__file__).resolve().parent.parent / "sql"
FILES = ["vulntrack_ddl.sql", "vulntrack_dml.sql", "vulntrack_objects.sql"]


def strip_comment(line):
    """Cut a trailing `-- comment`, ignoring dashes inside quoted strings."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif line.startswith("--", i):
            return line[:i]
    return line


def statements(text):
    delim, buf = ";", []
    for line in text.splitlines():
        line = strip_comment(line)
        s = line.strip()
        if s.upper().startswith("DELIMITER "):
            delim = s.split(None, 1)[1]
            continue
        if not s or s.startswith("--"):
            continue
        buf.append(line)
        if s.endswith(delim):
            stmt = "\n".join(buf).rstrip()
            yield stmt[: -len(delim)].rstrip()
            buf = []
    if buf:
        yield "\n".join(buf)


def main():
    try:
        con = pymysql.connect(host=DB["host"], port=DB["port"], user=DB["user"],
                              password=DB["password"], autocommit=True)
    except pymysql.MySQLError as e:
        sys.exit(f"Cannot connect to MySQL: {e}\nSet VT_DB_USER / VT_DB_PASSWORD (see config.py).")
    cur = con.cursor()
    n = 0
    for name in FILES:
        for stmt in statements((SQL / name).read_text(encoding="utf-8")):
            cur.execute(stmt)
            n += 1
        print(f"ok  {name}")
    # default login accounts (change these passwords from the Users page / Account page after first login)
    cur.execute("USE `%s`" % DB["database"])
    seed = [("admin", os.getenv("VT_ADMIN_PASSWORD", "Admin@123"), "admin"),
            ("analyst", os.getenv("VT_ANALYST_PASSWORD", "Analyst@123"), "analyst"),
            ("viewer", os.getenv("VT_VIEWER_PASSWORD", "Viewer@123"), "viewer")]
    for user, pw, role in seed:
        cur.execute("INSERT INTO APP_USER (username, password_hash, role) VALUES (%s,%s,%s)",
                    (user, generate_password_hash(pw), role))
    print("ok  default users: " + ", ".join(f"{u} ({r})" for u, _, r in seed))
    print(f"Done - {n} statements. Start the app with:  python app.py")


if __name__ == "__main__":
    main()
