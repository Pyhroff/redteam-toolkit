"""Regression tests for engagement session persistence and recording."""

import json

from core import session as session_module


def test_session_save_load_round_trip(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(session_module, "SESSIONS_DIR", tmp_path / "sessions")
    session = session_module.Session(target="127.0.0.1", name="Local test")
    session.log_port(443, "open", "https", "test-banner")
    session.log_finding(
        "XSS",
        "http://127.0.0.1:8000/lab",
        detail="local fixture",
        severity="high",
    )
    session.log_note("Scope is the local test fixture", category="scope")

    path = tmp_path / "session.json"
    session.save(str(path))
    loaded = session_module.Session.load(str(path))
    capsys.readouterr()

    assert loaded.session_id == session.session_id
    assert loaded.target == session.target
    assert loaded.name == session.name
    assert loaded.created_at == session.created_at
    assert loaded.updated_at == session.updated_at
    assert loaded.ports == session.ports
    assert loaded.findings == session.findings
    assert loaded.notes == session.notes
    assert json.loads(path.read_text(encoding="utf-8"))["target"] == "127.0.0.1"


def test_duplicate_port_does_not_replace_first_observation(capsys):
    session = session_module.Session(target="127.0.0.1")
    session.log_port(443, "open", "https", "first-banner")
    session.log_port(443, "open", "https", "second-banner")
    capsys.readouterr()

    assert len(session.ports) == 1
    assert session.ports[0]["banner"] == "first-banner"


def test_finding_severity_is_normalized(capsys):
    session = session_module.Session(target="127.0.0.1")
    session.log_finding("XSS", "http://127.0.0.1/", severity="high")
    capsys.readouterr()

    assert session.findings[0]["severity"] == "HIGH"


def test_legacy_session_without_updated_at_uses_created_at(tmp_path):
    path = tmp_path / "legacy-session.json"
    path.write_text(
        json.dumps({"target": "127.0.0.1", "created_at": "2026-01-02T03:04:05"}),
        encoding="utf-8",
    )

    loaded = session_module.Session.load(str(path))

    assert loaded.created_at == "2026-01-02T03:04:05"
    assert loaded.updated_at == loaded.created_at
