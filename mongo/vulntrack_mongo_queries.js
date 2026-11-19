// mongosh demo queries.   mongosh --file mongo/vulntrack_mongo_queries.js     (or paste into mongosh)
// Run `python app/setup_mongo.py` first.
use("vulntrack_docs");

print("1. All advisories actively exploited in the wild");
printjson(db.advisories.find({ exploited_in_wild: true }, { _id: 0, cve_id: 1, title: 1 }).toArray());

print("2. Advisories tagged 'rce' AND 'windows'");
printjson(db.advisories.find({ tags: { $all: ["rce", "windows"] } }, { _id: 0, cve_id: 1 }).toArray());

print("3. Most common tags (aggregation)");
printjson(db.advisories.aggregate([
  { $unwind: "$tags" }, { $group: { _id: "$tags", n: { $sum: 1 } } }, { $sort: { n: -1 } }, { $limit: 5 }]).toArray());

print("4. Scan reports per scanner and result");
printjson(db.scan_reports.aggregate([
  { $group: { _id: { scanner: "$scanner", status: "$status" }, n: { $sum: 1 } } }, { $sort: { "_id.scanner": 1 } }]).toArray());

print("5. Nessus reports only - query inside the nested raw document");
printjson(db.scan_reports.find({ "raw.plugin_id": { $exists: true } }, { _id: 0, asset: 1, cve_id: 1, "raw.plugin_id": 1 }).toArray());

print("6. Advisories with more than 2 mitigations");
printjson(db.advisories.find({ $expr: { $gt: [{ $size: "$mitigations" }, 2] } }, { _id: 0, cve_id: 1 }).toArray());

print("7. Notes for asset 8 (newest first)");
printjson(db.asset_notes.find({ asset_id: 8 }).sort({ created_at: -1 }).toArray());

print("8. Add a mitigation to one advisory ($push)");
db.advisories.updateOne({ cve_id: "CVE-2021-44228" }, { $push: { mitigations: "Block outbound LDAP/RMI at the firewall" } });
