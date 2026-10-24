from agenomics import EvidenceStore, Incident, IncidentSeverity
from agenomics.sanitize import redact


def test_redact_org_and_keys():
    text = "Rate limit reached for organization `org_01k3fvkr5jf3qr1f09stm5e8h9` key gsk_abcdefghij1234567890 Bearer abcdef123456"
    out = redact(text)
    assert "org_01" not in out and "gsk_abc" not in out and "abcdef123456" not in out
    assert "Rate limit reached" in out


def test_redact_keeps_plain_text_and_none():
    assert redact("timeout after 30 s") == "timeout after 30 s"
    assert redact(None) is None and redact("") == ""


def test_incident_description_is_redacted_in_store(tmp_path):
    store = EvidenceStore(str(tmp_path / "e.db"))
    store.record_observation(
        "a", 70.0, "Conditional",
        incidents=[Incident("429 for organization `org_ABCDEFGH12345`", IncidentSeverity.MINOR)])
    inc = store.get_observations("a")[0].incidents[0]
    desc = inc["description"] if isinstance(inc, dict) else inc.description
    assert "org_ABCDEFGH12345" not in desc and "[org-id]" in desc
    store.close()
