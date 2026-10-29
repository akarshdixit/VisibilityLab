"""Command line: registry-add, run, demo, verify.

Exit codes: 0 success, 1 a sample aborted on integrity or a seal failed to verify,
2 refused (prints "REFUSED: <reason>").
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .manifest import MANIFEST_NAME, verify_manifest
from .metrics import MEASURES
from .normalize import MappingError, load_mapping
from .registry import RegistryError, add_candidate
from .report import write_report, write_sample_report
from .run import SUMMARY_NAME, SYNTHETIC_NOTICE, GateError, run_batch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = PROJECT_ROOT / "fixtures"
DEMO_MAPPING_VERSION = "Synthetic mapping v1 (fixture, not the official ATT&CK export)"


def _refuse(reason: str) -> int:
    print(f"REFUSED: {reason}", file=sys.stderr)
    return 2


def _fmt(v) -> str:
    return f"{v:.4f}".rstrip("0").rstrip(".") if isinstance(v, float) and v not in (0.0,) else str(v)


def _print_summary(rows, out: Path, synthetic: bool) -> None:
    if synthetic:
        print(f"*** {SYNTHETIC_NOTICE} ***")
    for r in rows:
        print(f"\nSample {r['label'] or r['sample_sha256'][:12]}  ({r['sample_sha256'][:12]})  run={r['run_status']}")
        if r["run_status"] != "completed":
            print(f"  {r['note']}")
            continue
        print("  stages: " + "  ".join(f"{k}={r[f'stage_{k}']}" for k in "ABCS"))
        print("  " + "  ".join(f"{k}={_fmt(r[k])}" for k in MEASURES) + f"  S_overlap_C={r['S_overlap_C']}")
        print(f"  residual classes: {r['pk_summary']}  U={r['class_U']}")
        if r["note"]:
            print(f"  gate rejected: {r['note']}")
    print(f"\nOutputs written to {out}  (summary: {out / SUMMARY_NAME})")


def _do_run(specs: Path, mapping_path: Path, version: str, name: str | None, out: Path, collapse: bool) -> int:
    try:
        mapping = load_mapping(mapping_path, version, name)
        rows = run_batch(specs, mapping, out, collapse)
    except (GateError, MappingError) as exc:
        return _refuse(str(exc))
    _print_summary(rows, out, all(r["synthetic"] for r in rows))
    done = [r["sample_sha256"] for r in rows if r["run_status"] == "completed"]
    for sha in done:
        write_sample_report(out / sha[:12])
    print(f"HTML overview: {write_report(out, done)}  (per-sample report.html in each sample folder)")
    return 1 if any(r["run_status"] != "completed" for r in rows) else 0


def cmd_registry_add(args) -> int:
    try:
        row = add_candidate(args.file, args.sha256, args.source, args.retrieved, args.packer_label, args.note)
    except RegistryError as exc:
        return _refuse(str(exc))
    print(f"added {row['sha256']} to {args.file} with status {row['status']}")
    return 0


def cmd_run(args) -> int:
    return _do_run(Path(args.specs), Path(args.mapping), args.mapping_version, args.mapping_name,
                   Path(args.out), args.collapse_subtechniques)


def cmd_demo(args) -> int:
    print("Demo: bundled synthetic fixtures only. No real sample is read, unpacked or executed.")
    return _do_run(FIXTURES / "specs.json", FIXTURES / "attack_map.csv", DEMO_MAPPING_VERSION,
                   None, Path(args.out), False)


def cmd_verify(args) -> int:
    target = Path(args.dir)
    dirs = [target] if (target / MANIFEST_NAME).exists() else sorted(
        p for p in target.iterdir() if (p / MANIFEST_NAME).exists()
    ) if target.is_dir() else []
    if not dirs:
        return _refuse(f"no manifest found in {target}")
    failed = False
    for d in dirs:
        problems = verify_manifest(d)
        print(f"{d.name}: {'OK - seal holds' if not problems else 'FAILED'}")
        for p in problems:
            print(f"  - {p}")
        failed |= bool(problems)
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m pipeline", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("registry-add", help="add a candidate row to the register (metadata only)")
    r.add_argument("--file", required=True)
    r.add_argument("--sha256", required=True)
    r.add_argument("--source", required=True)
    r.add_argument("--retrieved", required=True, help="YYYY-MM-DD")
    r.add_argument("--packer-label", default="")
    r.add_argument("--note", default="")
    r.set_defaults(func=cmd_registry_add)

    run = sub.add_parser("run", help="run every sample in a specs file")
    run.add_argument("--specs", required=True)
    run.add_argument("--mapping", required=True, help="ATT&CK mapping table (CSV)")
    run.add_argument("--mapping-version", required=True)
    run.add_argument("--mapping-name", default=None)
    run.add_argument("--collapse-subtechniques", action="store_true", help="N3: collapse T####.### to T####")
    run.add_argument("--out", required=True)
    run.set_defaults(func=cmd_run)

    d = sub.add_parser("demo", help="run the bundled synthetic fixtures")
    d.add_argument("--out", default="out_demo")
    d.set_defaults(func=cmd_demo)

    v = sub.add_parser("verify", help="re-check manifest seals in an output folder")
    v.add_argument("--dir", required=True, help="a sample folder or a batch output folder")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
