"""Upload validation, storage isolation and Gate 3 rules for untrusted input."""

import io
import json
import zipfile

import pytest

from webapp.backend import storage
from webapp.backend.validation import ValidationError, extract_cape_labels, parse_pe_header, read_bundle

from .conftest import APPROVAL, capa_doc, make_pe, new_sample, recovery_doc, sha, upload

S1 = sha(b"test-double sample one")


@pytest.mark.parametrize(
    "kind, data, message",
    [
        ("A", b'{"rules": {', "malformed JSON"),
        ("A", b"[1, 2]", "top level must be a JSON object"),
        ("A", b'{"meta": {}}', "missing 'rules'"),
        ("S", b'{"labels": []}', "techniques"),
        ("A", capa_doc("f" * 64, {"r": ["T1055"]}), "not this sample"),
        ("B_recovery", recovery_doc("f" * 64, "e" * 64), "different sample"),
        ("B_recovery", b'{"check_source": "operator_tool"}', "sample_sha256"),
        ("cape_report", b'{"info": {}}', "target.file.sha256"),
        ("cape_report", json.dumps({"target": {"file": {"sha256": "f" * 64}}}).encode(), "different file"),
        ("A", json.dumps({"synthetic": True, "rules": {}}).encode(), "marked synthetic"),
    ],
)
def test_bad_evidence_is_rejected_with_a_clear_message(client, kind, data, message):
    s = new_sample(client, S1)
    r = upload(client, s["id"], kind, data)
    assert r.status_code == 400 and message in r.json()["detail"], r.text


def test_unknown_kind_oversize_and_duplicates(client, settings):
    s = new_sample(client, S1)
    assert upload(client, s["id"], "exe", b"{}").status_code == 400
    big = json.dumps({"rules": {}, "pad": "x" * (settings.max_json_bytes + 10)}).encode()
    assert upload(client, s["id"], "A", big).status_code == 413
    good = capa_doc(S1, {"r1": ["T1055"]})
    assert upload(client, s["id"], "A", good).status_code == 201
    dup = upload(client, s["id"], "A", good)
    assert dup.status_code == 409 and "already submitted" in dup.json()["detail"]
    # A different report for the same stage supersedes the old one (kept for audit).
    assert upload(client, s["id"], "A", capa_doc(S1, {"r2": ["T1027"]})).status_code == 201
    arts = client.get(f"/api/samples/{s['id']}").json()["artifacts"]
    assert sorted(a["superseded"] for a in arts if a["kind"] == "A") == [False, True]


def test_synthetic_samples_only_accept_synthetic_inputs(client):
    s = new_sample(client, S1, mode="synthetic")
    assert upload(client, s["id"], "A", capa_doc(S1, {"r": ["T1055"]})).status_code == 400


def test_gate3_and_pe_storage_switches(client, settings):
    assert client.post("/api/samples", json={"sha256": S1, "mode": "empirical", "source": "x",
                                             "retrieved": "2026-10-27"}).status_code == 403
    assert client.post("/api/samples", json={"sha256": S1, "mode": "empirical", "approval_id": "A1",
                                             "source": "x", "retrieved": "27-10-2026"}).status_code == 422
    s = new_sample(client, S1)
    r = upload(client, s["id"], "sample_pe", make_pe(), "x.exe")
    assert r.status_code == 403 and "disabled" in r.json()["detail"]
    settings.allow_sample_upload = True
    syn = new_sample(client, sha(b"syn"), mode="synthetic")
    assert upload(client, syn["id"], "sample_pe", make_pe(), "x.exe").status_code == 403


def test_pe_uploads_are_checked_hashed_and_quarantined(client, settings):
    settings.allow_sample_upload = True
    pe = make_pe(b"sample")
    s = new_sample(client, sha(pe))
    assert upload(client, s["id"], "sample_pe", b"MZ not really a PE", "a.exe").status_code == 400
    assert upload(client, s["id"], "sample_pe", make_pe(b"other"), "a.exe").status_code == 400  # hash mismatch
    r = upload(client, s["id"], "sample_pe", pe, "..\\..\\evil.exe")
    assert r.status_code == 201 and r.json()["original_name"] == "evil.exe"
    stored = list((settings.data_dir / "quarantine").iterdir())
    assert [p.name for p in stored] == [f"{sha(pe)}.sample"]
    assert client.get(f"/api/artifacts/{r.json()['id']}/download").status_code == 403  # never served
    detail = client.get(f"/api/samples/{s['id']}").json()["sample"]
    assert detail["file_stored"] and detail["pe_meta"]["format"] == "PE32"

    payload = make_pe(b"PAYLOAD")
    assert upload(client, s["id"], "payload_pe", payload).status_code == 400  # needs the record first
    assert upload(client, s["id"], "B_recovery", recovery_doc(sha(pe), sha(make_pe(b"x")))).status_code == 201
    r = upload(client, s["id"], "payload_pe", payload)
    assert r.status_code == 400 and "V2" in r.json()["detail"]


def test_create_sample_from_pe_computes_the_hash(client, settings):
    settings.allow_sample_upload = True
    pe = make_pe(b"from-pe")
    r = client.post("/api/samples/from-pe", data={"approval_id": APPROVAL, "source": "test double",
                                                  "retrieved": "2026-10-27"},
                    files={"file": ("s.exe", io.BytesIO(pe), "application/octet-stream")})
    assert r.status_code == 201 and r.json()["sha256"] == sha(pe)
    r2 = client.post("/api/samples/from-pe", data={"approval_id": APPROVAL, "source": "x", "retrieved": "2026-10-27"},
                     files={"file": ("s.exe", io.BytesIO(pe), "application/octet-stream")})
    assert r2.status_code == 409


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_bundles_accept_only_flat_known_names():
    with pytest.raises(ValidationError, match="not allowed"):
        read_bundle(_zip({"../../A.json": b"{}"}), 1 << 20)
    with pytest.raises(ValidationError, match="not allowed"):
        read_bundle(_zip({"payload.exe": b"MZ"}), 1 << 20)
    with pytest.raises(ValidationError, match="valid .zip"):
        read_bundle(b"not a zip", 1 << 20)
    with pytest.raises(ValidationError, match="expands"):
        read_bundle(_zip({"A.json": b"0" * 5000}), 1000)
    assert set(read_bundle(_zip({"A.json": b"{}", "C.json": b"{}"}), 1 << 20)) == {"A", "C"}


def test_bundle_upload_is_all_or_nothing(client):
    s = new_sample(client, S1)
    bad = _zip({"A.json": capa_doc(S1, {"r": ["T1055"]}), "C.json": b"{oops"})
    def post(z):
        return client.post(f"/api/samples/{s['id']}/bundle", files={"file": ("b.zip", io.BytesIO(z), "application/zip")})
    assert post(bad).status_code == 400
    assert client.get(f"/api/samples/{s['id']}").json()["artifacts"] == []
    good = _zip({"A.json": capa_doc(S1, {"r": ["T1055"]}), "C.json": capa_doc(S1, {"d": ["T1055"]})})
    r = post(good)
    assert r.status_code == 201 and len(r.json()["added"]) == 2


def test_storage_refuses_traversal_and_sanitizes_names():
    for bad in ("../x.json", "evidence/aa/../../../x.json", "quarantine/x.sample", "C:/Windows/x"):
        with pytest.raises(storage.StorageError):
            storage.storage_path(storage.Path("data"), bad)
    assert storage.safe_display_name("C:\\a\\b/<evil>.exe") == "_evil_.exe"


def test_pe_header_parser_and_cape_label_extraction():
    meta = parse_pe_header(make_pe())
    assert meta["machine"] == "i386" and meta["sections"][0]["name"] == ".text" and not meta["is_dotnet"]
    with pytest.raises(ValidationError):
        parse_pe_header(b"MZ" + b"\0" * 100)
    report = {"ttps": [{"signature": "a", "ttps": ["T1055", "T1112"]}, {"signature": "b", "ttp": "T1486"}, "junk"]}
    assert extract_cape_labels(report) == ["T1055", "T1112", "T1486"]
    assert extract_cape_labels({}) == []
