"""Visibility measures over the normalized technique sets.

A = packed static, B = validated payload static, C = dynamic reference,
S = sandbox's own labels (secondary; never part of the main measures).

A stage that is unavailable is passed as ``None``. Any measure that depends on
an unavailable stage, or whose denominator is empty, is ``"n/d"`` (not
defined) -- never 0, because 0 would claim the tool found nothing.
"""

from __future__ import annotations

from typing import Any

ND = "n/d"
MEASURES = ("QA", "VA", "VB", "DB", "IB", "G", "L", "M", "O")
DEFINITIONS = {
    "QA": "|A ∩ B| / |B|",
    "VA": "|A ∩ C| / |C|",
    "VB": "|B ∩ C| / |C|",
    "DB": "|(B ∩ C) \\ A| / |C|",
    "IB": "|C \\ B| / |C|",
    "G": "|B \\ A|",
    "L": "|A \\ B|",
    "M": "|B ∩ C|",
    "O": "|B \\ C|",
    "S_overlap_C": "|S ∩ C|",
}

def _needs(sets: dict[str, set[str] | None], *names: str) -> str | None:
    missing = [n for n in names if sets[n] is None]
    return f"stage {', '.join(missing)} not available" if missing else None


def _ratio(num: int, den: int) -> float:
    return round(num / den, 4)


def compute_metrics(
    A: set[str] | None,
    B: set[str] | None,
    C: set[str] | None,
    S: set[str] | None = None,
) -> dict[str, Any]:
    """Return {"measures": {...}, "inputs": {...}, "S_overlap_C": ..., "S_inputs": {...}}.

    ``inputs`` keeps numerator/denominator (or the n/d reason) for each measure,
    so every value can be recomputed by hand.
    """
    sets = {"A": A, "B": B, "C": C, "S": S}
    measures: dict[str, Any] = {}
    inputs: dict[str, dict[str, Any]] = {}

    def nd(name: str, reason: str) -> None:
        measures[name] = ND
        inputs[name] = {"reason": reason}

    def ratio(name: str, deps: tuple[str, ...], num_fn, den_name: str) -> None:
        reason = _needs(sets, *deps)
        if reason:
            return nd(name, reason)
        den = len(sets[den_name])
        if den == 0:
            return nd(name, f"{den_name} is empty (zero denominator)")
        num = num_fn()
        measures[name] = _ratio(num, den)
        inputs[name] = {"numerator": num, "denominator": den}

    def count(name: str, deps: tuple[str, ...], fn, needs_c: bool = False) -> None:
        reason = _needs(sets, *deps)
        if reason:
            return nd(name, reason)
        if needs_c and not C:
            return nd(name, "C is empty (no dynamic reference)")
        measures[name] = int(fn())
        inputs[name] = {"count": measures[name]}

    ratio("QA", ("A", "B"), lambda: len(A & B), "B")
    ratio("VA", ("A", "C"), lambda: len(A & C), "C")
    ratio("VB", ("B", "C"), lambda: len(B & C), "C")
    ratio("DB", ("A", "B", "C"), lambda: len((B & C) - A), "C")
    ratio("IB", ("B", "C"), lambda: len(C - B), "C")
    count("G", ("A", "B"), lambda: len(B - A))
    count("L", ("A", "B"), lambda: len(A - B))
    count("M", ("B", "C"), lambda: len(B & C), needs_c=True)
    count("O", ("B", "C"), lambda: len(B - C), needs_c=True)

    # Secondary count, reported beside the measures (not part of them).
    s_reason = _needs(sets, "S", "C")
    if s_reason:
        s_overlap, s_inputs = ND, {"reason": s_reason}
    elif not C:
        s_overlap, s_inputs = ND, {"reason": "C is empty (no dynamic reference)"}
    else:
        s_overlap = len(S & C)
        s_inputs = {"count": s_overlap}

    return {
        "measures": {k: measures[k] for k in MEASURES},
        "inputs": {k: inputs[k] for k in MEASURES},
        "S_overlap_C": s_overlap,
        "S_inputs": s_inputs,
    }
