"""Regression tests for race-safe recon worker queues."""

import ast
import threading
from queue import Queue
from pathlib import Path

from recon import network_mapper, port_scanner


class AlwaysNonEmptyQueue(Queue):
    """Expose the old empty()/get() race deterministically."""

    def empty(self):
        return False


def _run_workers(worker, args_factory, items):
    work = AlwaysNonEmptyQueue()
    for item in items:
        work.put(item)

    workers = [
        threading.Thread(target=worker, args=args_factory(work), daemon=True)
        for _ in range(8)
    ]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in workers)
    assert work.unfinished_tasks == 0


def test_port_scanner_workers_drain_queue_without_blocking(monkeypatch):
    seen = []
    lock = threading.Lock()

    def fake_scan(ip, port, grab, timeout):
        with lock:
            seen.append(port)

    monkeypatch.setattr(port_scanner, "scan_port", fake_scan)
    ports = list(range(1, 151))
    _run_workers(
        port_scanner.worker,
        lambda q: (q, "127.0.0.1", False, 0.01),
        ports,
    )

    assert sorted(seen) == ports


def test_network_mapper_workers_drain_queue_without_blocking(monkeypatch):
    seen = []
    lock = threading.Lock()

    def fake_scan(ip, method, scan_ports, deep):
        with lock:
            seen.append(ip)

    monkeypatch.setattr(network_mapper, "scan_host", fake_scan)
    hosts = [f"192.0.2.{i}" for i in range(1, 151)]
    _run_workers(
        network_mapper.worker,
        lambda q: (q, "tcp", [22, 80], False),
        hosts,
    )

    assert sorted(seen) == sorted(hosts)


def test_all_recon_queue_workers_use_nonblocking_retrieval():
    root = Path(__file__).resolve().parents[1]
    paths = (
        "recon/port_scanner.py",
        "recon/network_mapper.py",
        "recon/subdomain_enum.py",
        "recon/dir_fuzzer.py",
    )
    for relative in paths:
        source = (root / relative).read_text(encoding="utf-8")
        ast.parse(source)
        assert "get_nowait()" in source, relative
        assert "while not queue.empty()" not in source, relative
        assert "while not q.empty()" not in source, relative
