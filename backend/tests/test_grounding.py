"""Anti-hallucination guard + rulebook integrity."""
from app.detect import mitre
from app.narrate import grounding


def test_grounding_accepts_grounded_narrative():
    text = ("PowerShell connected to 185.220.101.5 which maps to T1071. "
            "This resembles command-and-control.")
    res = grounding.check(text, allowed_ips={"185.220.101.5"}, allowed_techniques={"T1071"})
    assert res.ok
    assert res.violations == []


def test_grounding_rejects_invented_ip():
    text = "The host beaconed to 8.8.8.8 (T1071)."
    res = grounding.check(text, allowed_ips={"185.220.101.5"}, allowed_techniques={"T1071"})
    assert not res.ok
    assert any("8.8.8.8" in v for v in res.violations)


def test_grounding_rejects_invented_technique():
    text = "This is credential dumping T1003."
    res = grounding.check(text, allowed_ips=set(), allowed_techniques={"T1071"})
    assert not res.ok
    assert any("T1003" in v for v in res.violations)


def test_rulebook_all_signal_techniques_in_catalog():
    """Every technique referenced by a signal must exist in the catalog."""
    catalog = mitre.all_technique_ids()
    for signal in ["rule:encoded_powershell", "rule:office_spawn_shell",
                   "rarity:process_name", "rarity:dest_ip"]:
        refs = mitre.techniques_for(signal)
        assert refs, f"{signal} has no MITRE mapping"
        for ref in refs:
            assert ref.technique_id in catalog
            assert ref.tactic != "Unknown"
