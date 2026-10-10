"""Regression tests for concurrent port scanning."""

from core import orchestrator


class FakeSocket:
    def __init__(self, *args):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, address):
        return 0 if address[1] % 3 == 0 else 1


def test_quick_scan_processes_all_ports_with_multiple_workers(monkeypatch):
    monkeypatch.setattr(orchestrator.socket, "socket", FakeSocket)
    ports = list(range(1, 151))

    result = orchestrator.quick_scan("127.0.0.1", ports, timeout=0.01)

    assert result == [port for port in ports if port % 3 == 0]


def test_quick_scan_with_no_ports_returns_empty_list():
    assert orchestrator.quick_scan("127.0.0.1", []) == []
