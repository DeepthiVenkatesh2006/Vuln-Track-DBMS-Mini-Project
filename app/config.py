"""Database settings. Override with environment variables, e.g.
   set VT_DB_PASSWORD=mypassword   (Windows)   /   export VT_DB_PASSWORD=mypassword  (Linux/Mac)"""
import os

DB = dict(
    host=os.getenv("VT_DB_HOST", "localhost"),
    port=int(os.getenv("VT_DB_PORT", "3306")),
    user=os.getenv("VT_DB_USER", "root"),
    password=os.getenv("VT_DB_PASSWORD", ""),
    database=os.getenv("VT_DB_NAME", "vulntrack"),
)
SECRET_KEY = os.getenv("VT_SECRET", "vulntrack-dev-key")

# MongoDB (second database: flexible documents - advisories, raw scan reports, analyst notes)
MONGO_URI = os.getenv("VT_MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("VT_MONGO_DB", "vulntrack_docs")
