"""MongoDB helpers (PyMongo). MySQL keeps the structured data; MongoDB keeps flexible documents:
   advisories (1 per CVE), scan_reports (raw scanner output, shape differs per scanner), asset_notes.
   Set VT_MONGO_MOCK=1 to use an in-memory fake (mongomock) - handy for a quick demo without mongod."""
import os
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from config import MONGO_URI, MONGO_DB

_client = None


def client():
    global _client
    if _client is None:
        if os.getenv("VT_MONGO_MOCK") == "1":
            import mongomock
            _client = mongomock.MongoClient()
        else:
            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    return _client


def mdb():
    return client()[MONGO_DB]


def ping():
    """True if MongoDB answers."""
    try:
        client().admin.command("ping")
        return True
    except PyMongoError:
        return False


def ensure_indexes():
    d = mdb()
    d.advisories.create_index("cve_id", unique=True)
    d.advisories.create_index("tags")
    d.advisories.create_index([("title", "text"), ("summary", "text")])
    d.scan_reports.create_index([("asset_id", 1), ("scan_date", -1)])
    d.scan_reports.create_index("cve_id")
    d.asset_notes.create_index([("asset_id", 1), ("created_at", -1)])
