"""TEST DOUBLE for the capa command line. Used only by the backend tests.

`--version` prints a fixed version. `-j -f pe <file>` hashes the file (it never
executes it) and prints capa-shaped JSON with fixed fictional techniques;
`-f cape <report>` reads target.file.sha256 from the report. A file whose bytes
contain b"FAIL" makes it exit 1, to test tool failures.
"""

import hashlib
import json
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("capa 9.9.9-test-double")
    sys.exit(0)
path = args[-1]
data = open(path, "rb").read()
if b"FAIL" in data:
    print("simulated capa failure", file=sys.stderr)
    sys.exit(1)
fmt = args[args.index("-f") + 1]
if fmt == "cape":
    sample = json.loads(data)["target"]["file"]["sha256"]
    rules = {"dyn-1": ["T1055"], "dyn-2": ["T1112"]}
else:
    sample = hashlib.sha256(data).hexdigest()
    rules = {"stat-1": ["T1055"], "stat-2": ["T1027"]} if b"PAYLOAD" not in data else {"pay-1": ["T1055", "T1112"]}
print(json.dumps({"meta": {"version": "9.9.9-test-double", "sample": {"sha256": sample}},
                  "rules": {n: {"meta": {"attack": [{"id": t} for t in ids]}} for n, ids in rules.items()}}))
