"""Parses sql/vulntrack_queries.sql so the web page and the .sql file can never drift apart."""
import re
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / "sql" / "vulntrack_queries.sql"
HEAD = re.compile(r"^-- (Q\d+) \| (.+?) \| (.+)$")


def load():
    out, cur = [], None
    for line in PATH.read_text(encoding="utf-8").splitlines():
        m = HEAD.match(line)
        if m:
            cur = dict(id=m[1], category=m[2], title=m[3], desc="", sql=[])
            out.append(cur)
        elif cur is not None:
            if line.startswith("-- ==="):
                cur = None
            elif line.startswith("--") and not cur["sql"]:
                cur["desc"] += line[2:].strip() + " "
            elif line.strip() or cur["sql"]:
                cur["sql"].append(line)
    for q in out:
        q["sql"] = "\n".join(q["sql"]).strip()
        q["desc"] = q["desc"].strip()
    return out
