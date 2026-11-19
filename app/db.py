"""Thin PyMySQL helpers. Every request opens a short-lived autocommit connection."""
import pymysql
import pymysql.cursors
from config import DB


def connect(**extra):
    return pymysql.connect(cursorclass=pymysql.cursors.DictCursor, autocommit=True,
                           charset="utf8mb4", **{**DB, **extra})


def query(sql, args=()):
    """Run a SELECT, return list of dict rows."""
    con = connect()
    try:
        with con.cursor() as cur:
            cur.execute(sql, args)
            return list(cur.fetchall())
    finally:
        con.close()


def one(sql, args=()):
    rows = query(sql, args)
    return rows[0] if rows else None


def execute(sql, args=()):
    """Run INSERT/UPDATE/DELETE/CALL and return affected row count."""
    con = connect()
    try:
        with con.cursor() as cur:
            return cur.execute(sql, args)
    finally:
        con.close()


def run_any(sql):
    """Run a stored demo query (SELECT or CALL). Returns (columns, rows)."""
    con = connect()
    try:
        with con.cursor() as cur:
            cur.execute(sql)
            rows = list(cur.fetchall())
            cols = [c[0] for c in cur.description] if cur.description else []
            while cur.nextset():     # CALL leaves an extra OK packet behind
                pass
            return cols, rows
    finally:
        con.close()
