"""Invariants of the evaluation harness: the properties that make its numbers meaningful."""
import importlib.util
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


gen, metrics = _load("generate_demo_data"), _load("metrics")


def _write(tmp, seed):
    out = tmp / f"o{seed}"
    sys.argv = ["x", "--seed", str(seed), "--out", str(out)]
    gen.main()
    return out


def test_generator_is_deterministic(tmp_path):
    a, b = _write(tmp_path, 7), _write(tmp_path / "b", 7)
    assert (a / "normal/baseline_normal.json").read_text() == (b / "normal/baseline_normal.json").read_text()


def test_splits_are_disjoint_in_time_and_entity(tmp_path):
    out = _write(tmp_path, 1)
    load = lambda f: json.load(open(out / "normal" / f))                       # noqa: E731
    train, known, unseen = load("baseline_normal.json"), load("heldout_known.json"), load("heldout_unseen.json")
    assert max(r["timestamp"] for r in train) < min(r["timestamp"] for r in known)
    users = lambda rs: {r["user"] for r in rs}                                 # noqa: E731
    assert users(known) <= users(train)
    assert users(unseen).isdisjoint(users(train))
    assert len(users(train)) >= 5


def test_baseline_never_trains_on_rule_hits(tmp_path):
    f = tmp_path / "t.json"
    rec = {"timestamp": "2026-03-02T10:00:00+00:00", "host": "H", "user": "u", "event": {"category": ["process"]},
           "process": {"name": "powershell.exe", "parent": {"name": "winword.exe"},
                       "command_line": "powershell -enc ZQBjAGgAbwA="}}
    f.write_text(json.dumps([rec] * 100))
    _fn, info = metrics.build_baseline(str(f))
    assert info["train_events"] == 0 and info["train_skipped_rule_hits"] == 100


def test_benign_rule_adjacent_activity_never_reaches_high(tmp_path):
    out = _write(tmp_path, 3)
    fn, _ = metrics.build_baseline(str(out / "normal/baseline_normal.json"))
    for name in ("heldout_known.json", "heldout_unseen.json"):
        res = metrics.false_positives(str(out / "normal" / name), fn, metrics.SEV_RANK["high"])
        assert res["false_positives"] == 0, (name, res)
