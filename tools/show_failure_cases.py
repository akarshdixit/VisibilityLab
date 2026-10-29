"""Live demonstration of the gates, on throw-away copies of the synthetic fixtures.

Each case copies fixtures/ to a temp folder, breaks one thing, runs the real CLI
in a subprocess and prints its exit code and output. The bundled fixtures are
never modified.

Run from the project root:  python tools/show_failure_cases.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cli(*args: str, tmp: str = "") -> None:
    proc = subprocess.run([sys.executable, "-m", "pipeline", *args], cwd=ROOT,
                          capture_output=True, text=True)

    def short(text: str) -> str:
        return text.replace(tmp, "<tmp>") if tmp else text

    print(short(f"$ python -m pipeline {' '.join(args)}"))
    print(f"exit code: {proc.returncode}")
    for line in (proc.stdout + proc.stderr).strip().splitlines():
        if line.strip():
            print(f"  | {short(line)}")


def case(title: str, mutate) -> None:
    print("\n" + "=" * 78 + f"\nCASE: {title}\n" + "=" * 78)
    with tempfile.TemporaryDirectory() as tmp:
        fx = Path(tmp) / "fixtures"
        shutil.copytree(ROOT / "fixtures", fx)
        specs = json.loads((fx / "specs.json").read_text(encoding="utf-8"))
        mutate(fx, specs)
        (fx / "specs.json").write_text(json.dumps(specs, indent=2), encoding="utf-8")
        cli("run", "--specs", str(fx / "specs.json"), "--mapping", str(fx / "attack_map.csv"),
            "--mapping-version", "Synthetic mapping v1", "--out", str(Path(tmp) / "out"), tmp=tmp)
        if (Path(tmp) / "out").exists() and title.startswith("4"):
            cli("verify", "--dir", str(Path(tmp) / "out"), tmp=tmp)


def pilot_without_approval(fx, specs):
    specs[0]["mode"] = "pilot"
    specs[0]["approval_id"] = None


def payload_without_record(fx, specs):
    del specs[0]["inputs"]["B_recovery"]
    del specs[0]["input_sha256"]["B_recovery"]


def changed_input(fx, specs):
    path = fx / specs[0]["inputs"]["C"]
    path.write_text(path.read_text(encoding="utf-8").replace("T1112", "T1113"), encoding="utf-8")


def sandbox_as_proof(fx, specs):
    path = fx / specs[0]["inputs"]["B_recovery"]
    rec = json.loads(path.read_text(encoding="utf-8"))
    rec["check_source"] = "sandbox"
    path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    specs[0]["input_sha256"]["B_recovery"] = hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    print("All cases run on temporary copies of SYNTHETIC fixtures.")
    case("1 Gate 3: pilot mode without an approval reference", pilot_without_approval)
    case("2 Payload gate: B supplied without a recovery record", payload_without_record)
    case("3 Hash gate: an input file changed after its hash was recorded", changed_input)
    case("4 Recovery gate: a sandbox trace offered as recovery proof", sandbox_as_proof)
    print("\n" + "=" * 78 + "\nCASE: 5 Registry: duplicate hash and bad date\n" + "=" * 78)
    with tempfile.TemporaryDirectory() as tmp:
        reg = str(Path(tmp) / "register.csv")
        h = hashlib.sha256(b"SYNTHETIC register example").hexdigest().upper()
        cli("registry-add", "--file", reg, "--sha256", h, "--source", "synthetic test", "--retrieved", "2026-10-27", tmp=tmp)
        cli("registry-add", "--file", reg, "--sha256", h, "--source", "synthetic test", "--retrieved", "2026-10-27", tmp=tmp)
        cli("registry-add", "--file", reg, "--sha256", "a" * 64, "--source", "synthetic test", "--retrieved", "27-10-2026", tmp=tmp)
