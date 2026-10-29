"""Convert the official MITRE ATT&CK Enterprise STIX bundle into the pipeline's mapping CSV.

The STIX bundle is NOT stored in this repository. Download it yourself, e.g.

    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json

then run, from the project root:

    python tools/build_attack_map.py <path to enterprise-attack-20.0.json>

Writes mappings/attack_enterprise_v20.0.csv and a provenance JSON recording the
bundle's SHA-256 and collection version, so every manifest can be traced to the
exact upstream file.

Row status rules (normalization N4):
  current     attack-pattern neither revoked nor deprecated
  revoked     revoked, following the revoked-by chain to a final *current* technique
  deprecated  deprecated, or revoked with no current final replacement (kept and flagged)
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack-{v}.json")


def external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
            return ref["external_id"]
    return None


def build(stix_path: Path) -> tuple[Path, dict]:
    data = stix_path.read_bytes()
    bundle = json.loads(data)
    objects = bundle["objects"]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    version = collection["x_mitre_version"]

    patterns = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    revoked_by = {o["source_ref"]: o["target_ref"] for o in objects
                  if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"
                  and o["source_ref"] in patterns}

    def state(o: dict) -> str:
        if o.get("revoked"):
            return "revoked"
        return "deprecated" if o.get("x_mitre_deprecated") else "current"

    def final_target(stix_id: str) -> dict | None:
        seen = set()
        while stix_id in revoked_by and stix_id not in seen:
            seen.add(stix_id)
            stix_id = revoked_by[stix_id]
        target = patterns.get(stix_id)
        return target if target and state(target) == "current" else None

    rows: dict[str, tuple[str, str, str]] = {}
    for o in patterns.values():
        tid = external_id(o)
        if not tid:
            continue
        st, repl, note = state(o), "", o.get("name", "")
        if st == "revoked":
            target = final_target(o["id"])
            if target and external_id(target) and external_id(target) != tid:
                repl = external_id(target)
                note = f"{note} (revoked; replaced by {repl})"
            else:
                st, note = "deprecated", f"{note} (revoked; no current replacement)"
        prev = rows.get(tid)
        if prev is None or (prev[0] != "current" and st == "current"):
            rows[tid] = (st, repl, note)

    out_dir = ROOT / "mappings"
    out_dir.mkdir(exist_ok=True)
    csv_path = out_dir / f"attack_enterprise_v{version}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["technique_id", "status", "replacement", "note"])
        for tid in sorted(rows):
            w.writerow([tid, *rows[tid]])

    counts = {s: sum(1 for r in rows.values() if r[0] == s) for s in ("current", "revoked", "deprecated")}
    provenance = {
        "name": csv_path.name,
        "attack_domain": "enterprise-attack",
        "attack_version": version,
        "source_url": SOURCE_URL.format(v=version),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "csv_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "rows": counts,
        "generator": "tools/build_attack_map.py",
    }
    (out_dir / f"attack_enterprise_v{version}.provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8", newline="\n")
    return csv_path, provenance


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tools/build_attack_map.py <enterprise-attack-XX.json>")
    path, prov = build(Path(sys.argv[1]))
    print(json.dumps(prov, indent=2))
