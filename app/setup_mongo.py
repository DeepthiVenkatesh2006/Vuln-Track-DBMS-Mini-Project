"""Seed MongoDB:  python setup_mongo.py      (run AFTER setup_db.py - it reads CVEs/scans from MySQL)
Drops and recreates the `vulntrack_docs` collections: advisories, scan_reports, asset_notes."""
import sys
import zlib
from datetime import datetime, timedelta

import db
import mongo_db

# Curated advisory documents. Fields are deliberately NOT identical across documents -
# that flexibility is the reason these live in MongoDB rather than in MySQL tables.
ADV = {
    "CVE-2021-44228": dict(title="Log4Shell - Apache Log4j2 JNDI remote code execution", cwe="CWE-502", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Apache", "product": "Log4j2", "versions": "2.0-beta9 to 2.14.1"}],
        mitigations=["Upgrade to Log4j 2.17.1 or later", "Set -Dlog4j2.formatMsgNoLookups=true (partial)", "Remove JndiLookup.class from the jar"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"], tags=["rce", "java", "internet-facing"]),
    "CVE-2014-0160": dict(title="Heartbleed - OpenSSL TLS heartbeat memory disclosure", cwe="CWE-126", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "OpenSSL", "product": "OpenSSL", "versions": "1.0.1 to 1.0.1f"}],
        mitigations=["Upgrade to OpenSSL 1.0.1g+", "Revoke and reissue TLS certificates", "Rotate credentials and session keys"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"], tags=["tls", "info-leak", "openssl"]),
    "CVE-2017-0144": dict(title="EternalBlue - SMBv1 remote code execution", cwe="CWE-119", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Microsoft", "product": "Windows SMBv1", "versions": "Vista - Server 2016"}],
        mitigations=["Apply MS17-010", "Disable SMBv1", "Block TCP 445 at the perimeter"],
        references=["https://learn.microsoft.com/security-updates/securitybulletins/2017/ms17-010"], tags=["rce", "smb", "wannacry", "windows"]),
    "CVE-2019-0708": dict(title="BlueKeep - RDP pre-auth remote code execution", cwe="CWE-416", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Microsoft", "product": "Remote Desktop Services", "versions": "Win7, Server 2008/R2"}],
        mitigations=["Apply May 2019 security update", "Enable Network Level Authentication", "Restrict TCP 3389"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"], tags=["rce", "rdp", "wormable", "windows"]),
    "CVE-2020-1472": dict(title="Zerologon - Netlogon privilege escalation to domain admin", cwe="CWE-330", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Microsoft", "product": "Netlogon (Domain Controllers)", "versions": "Server 2008 R2 - 2019"}],
        mitigations=["Install August 2020 update", "Enable DC enforcement mode", "Monitor Event IDs 5827-5831"],
        references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"], tags=["privesc", "active-directory", "windows"]),
    "CVE-2022-22965": dict(title="Spring4Shell - Spring Framework data-binding RCE", cwe="CWE-94", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "VMware", "product": "Spring Framework", "versions": "5.3.0-5.3.17, 5.2.0-5.2.19"}],
        mitigations=["Upgrade to Spring 5.3.18 / 5.2.20", "Upgrade Tomcat", "Use DataBinder disallowedFields"],
        references=["https://spring.io/security/cve-2022-22965"], tags=["rce", "java", "web"]),
    "CVE-2018-11776": dict(title="Apache Struts namespace OGNL remote code execution", cwe="CWE-20", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Apache", "product": "Struts", "versions": "2.3 - 2.3.34, 2.5 - 2.5.16"}],
        mitigations=["Upgrade to Struts 2.3.35 / 2.5.17", "Set alwaysSelectFullNamespace to false"],
        references=["https://cwiki.apache.org/confluence/display/WW/S2-057"], tags=["rce", "java", "web"]),
    "CVE-2021-34527": dict(title="PrintNightmare - Windows Print Spooler RCE", cwe="CWE-269", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Microsoft", "product": "Windows Print Spooler", "versions": "all supported Windows"}],
        mitigations=["Apply July 2021 out-of-band update", "Disable Print Spooler on servers that do not print"],
        references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"], tags=["rce", "privesc", "windows"]),
    "CVE-2021-3156": dict(title="Baron Samedit - sudo heap overflow to root", cwe="CWE-193", attack_vector="Local",
        exploited_in_wild=False, affected_products=[{"vendor": "Sudo Project", "product": "sudo", "versions": "1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1"}],
        mitigations=["Upgrade sudo to 1.9.5p2+", "Test with: sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')"],
        references=["https://www.sudo.ws/security/advisories/unescape_overflow/"], tags=["privesc", "linux", "local"]),
    "CVE-2021-26855": dict(title="ProxyLogon - Exchange Server SSRF leading to RCE", cwe="CWE-918", attack_vector="Network",
        exploited_in_wild=True, affected_products=[{"vendor": "Microsoft", "product": "Exchange Server", "versions": "2013, 2016, 2019"}],
        mitigations=["Install March 2021 Exchange security updates", "Run Microsoft EOMT script", "Hunt for web shells in OWA directories"],
        references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"], tags=["rce", "exchange", "internet-facing", "windows"]),
    "CVE-2022-30190": dict(title="Follina - MSDT remote code execution via Office documents", cwe="CWE-610", attack_vector="Local",
        exploited_in_wild=True, affected_products=[{"vendor": "Microsoft", "product": "Windows MSDT / Office", "versions": "Office 2013 - 2021"}],
        mitigations=["Apply June 2022 cumulative update", "Remove the ms-msdt URL protocol handler registry key"],
        references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190"], tags=["rce", "phishing", "office", "windows"]),
    "CVE-2011-3389": dict(title="BEAST - SSL 3.0 / TLS 1.0 CBC plaintext recovery", cwe="CWE-326", attack_vector="Network",
        exploited_in_wild=False, affected_products=[{"vendor": "Multiple", "product": "SSL 3.0 / TLS 1.0 implementations", "versions": "n/a"}],
        mitigations=["Disable TLS 1.0 and SSL 3.0", "Prefer TLS 1.2+ cipher suites"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"], tags=["tls", "crypto"]),
    "CVE-2015-4000": dict(title="Logjam - weak Diffie-Hellman (512-bit export) downgrade", cwe="CWE-310", attack_vector="Network",
        exploited_in_wild=False, affected_products=[{"vendor": "Multiple", "product": "TLS servers with DHE_EXPORT", "versions": "n/a"}],
        mitigations=["Disable DHE_EXPORT cipher suites", "Use 2048-bit or larger DH groups"],
        references=["https://weakdh.org/"], tags=["tls", "crypto"]),
}

NOTES = [
    ("WebServer-01", "sec-analyst", "Log4j upgraded to 2.17.1 during the August maintenance window; verified with a re-scan.", ["patched", "verified"]),
    ("DomainController-01", "sec-analyst", "Zerologon still open. Waiting for the change-approval board - enforcement mode must be tested first.", ["blocked", "change-request"]),
    ("DomainController-01", "it-ops", "Enforcement-mode test scheduled on the staging DC next week.", ["scheduled"]),
    ("MailServer-01", "sec-analyst", "Exchange is internet-facing. Checked OWA directories for web shells - none found.", ["hunt", "clean"]),
    ("FileServer-01", "it-ops", "Legacy Windows 7 box, scheduled for decommission. Compensating control: TCP 3389 blocked at the VLAN firewall.", ["legacy", "compensating-control"]),
]


def raw_blob(scanner, cve, adv, asset):
    """Raw scanner output - different shape per scanner (this is why it is a document, not a row)."""
    if scanner == "Nessus":
        return {"plugin_id": 100000 + zlib.crc32(cve.encode()) % 99999, "risk_factor": "High", "port": 443,
                "protocol": "tcp", "plugin_output": f"Detected {adv.get('title', cve)} on {asset}"}
    return {"nvt": {"oid": "1.3.6.1.4.1.25623.1.0." + str(zlib.crc32(cve.encode()) % 999999), "name": cve},
            "qod": {"value": 80, "type": "remote_banner"}, "threat": "High", "host": asset}


def main():
    if not mongo_db.ping():
        sys.exit("Cannot reach MongoDB. Start it first (see README), or check VT_MONGO_URI.")
    d = mongo_db.mdb()
    for c in ("advisories", "scan_reports", "asset_notes"):
        d[c].drop()

    vulns = db.query("SELECT vuln_id, cve_id, description, published_date FROM VULNERABILITY")
    now = datetime.utcnow()
    docs = []
    for v in vulns:
        a = dict(ADV.get(v["cve_id"], {"title": v["cve_id"], "mitigations": [], "references": [], "tags": []}))
        a.update(cve_id=v["cve_id"], summary=v["description"], exploit_available=bool(a.get("exploited_in_wild")),
                 updated_at=now, updated_by="seed")
        docs.append(a)
    d.advisories.insert_many(docs)

    adv_by_cve = {a["cve_id"]: a for a in docs}
    reports = []
    for s in db.query("""SELECT s.asset_id, a.name asset, v.cve_id, s.scan_date, s.scanner_used, s.detection_status
                         FROM SCAN_RESULTS s JOIN ASSET a ON a.asset_id=s.asset_id
                         JOIN VULNERABILITY v ON v.vuln_id=s.vuln_id"""):
        reports.append(dict(asset_id=s["asset_id"], asset=s["asset"], cve_id=s["cve_id"],
                            scan_date=datetime.combine(s["scan_date"], datetime.min.time()),
                            scanner=s["scanner_used"], status=s["detection_status"],
                            raw=raw_blob(s["scanner_used"], s["cve_id"], adv_by_cve[s["cve_id"]], s["asset"])))
    if reports:
        d.scan_reports.insert_many(reports)

    ids = {r["name"]: r["asset_id"] for r in db.query("SELECT asset_id, name FROM ASSET")}
    notes = []
    for i, (asset, author, text, tags) in enumerate(NOTES):
        if asset in ids:
            notes.append(dict(asset_id=ids[asset], author=author, text=text, tags=tags,
                              created_at=now - timedelta(days=len(NOTES) - i)))
    if notes:
        d.asset_notes.insert_many(notes)

    mongo_db.ensure_indexes()
    print(f"ok  MongoDB '{mongo_db.MONGO_DB}': {len(docs)} advisories, {len(reports)} scan_reports, {len(notes)} asset_notes")


if __name__ == "__main__":
    main()
