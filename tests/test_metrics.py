"""Measures: hand-computed values, n/d rules and the IB = 1 - VB identity."""

import itertools

from pipeline.metrics import ND, compute_metrics

# Worked example from the Review 2 guide (normalized sets; fictional IDs).
A = {"T1055", "T1027", "T1082"}
B = {"T1055", "T1027", "T1082", "T1497"}
C = {"T1055", "T1027", "T1112", "T1620", "T9998"}
S = {"T1055", "T1486"}


def test_worked_example_matches_hand_computation():
    m = compute_metrics(A, B, C, S)
    assert m["measures"] == {
        "QA": 0.75, "VA": 0.4, "VB": 0.4, "DB": 0.0, "IB": 0.6,
        "G": 1, "L": 0, "M": 2, "O": 2,
    }
    assert m["S_overlap_C"] == 1
    assert m["inputs"]["QA"] == {"numerator": 3, "denominator": 4}
    assert m["inputs"]["IB"] == {"numerator": 3, "denominator": 5}


def test_ib_equals_one_minus_vb_whenever_defined():
    universe = ["T1", "T2", "T3", "T4"]
    subsets = [set(c) for r in range(len(universe) + 1) for c in itertools.combinations(universe, r)]
    checked = 0
    for b, c in itertools.product(subsets, subsets):
        m = compute_metrics(set(), b, c)["measures"]
        if m["VB"] == ND:
            assert m["IB"] == ND
            continue
        assert abs(m["IB"] - (1 - m["VB"])) < 1e-4
        checked += 1
    assert checked > 200


def test_b_not_recovered_makes_b_measures_nd_but_keeps_va():
    m = compute_metrics(A, None, C, S)["measures"]
    assert m["VA"] == 0.4
    for k in ("QA", "VB", "DB", "IB", "G", "L", "M", "O"):
        assert m[k] == ND, k


def test_empty_recovered_b_only_zero_denominator_is_nd():
    m = compute_metrics(A, set(), C)["measures"]
    assert m["QA"] == ND  # |B| = 0
    assert m["VB"] == 0.0 and m["IB"] == 1.0  # real values: the payload matched nothing
    assert m["G"] == 0 and m["L"] == 3


def test_empty_c_makes_dynamic_measures_nd():
    m = compute_metrics(A, B, set(), S)
    for k in ("VA", "VB", "DB", "IB", "M", "O"):
        assert m["measures"][k] == ND, k
    assert m["measures"]["QA"] == 0.75 and m["measures"]["G"] == 1 and m["measures"]["L"] == 0
    assert m["S_overlap_C"] == ND


def test_failed_a_makes_a_measures_nd():
    m = compute_metrics(None, B, C)["measures"]
    for k in ("QA", "VA", "DB", "G", "L"):
        assert m[k] == ND, k
    assert (m["VB"], m["IB"], m["M"], m["O"]) == (0.4, 0.6, 2, 2)


def test_rounding_and_count_types():
    m = compute_metrics({"T1"}, {"T1", "T2", "T3"}, {"T1", "T2", "T3"})["measures"]
    assert m["QA"] == 0.3333 and m["DB"] == 0.6667
    for k in ("G", "L", "M", "O"):
        assert type(m[k]) is int


def test_sandbox_overlap_is_separate_and_nd_without_s():
    m = compute_metrics(A, B, C, None)
    assert "S_overlap_C" not in m["measures"]
    assert m["S_overlap_C"] == ND
