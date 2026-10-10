# Changelog

## 2026-10-10

- Fix recon worker queue races in the port scanner, network mapper, subdomain enumerator, and directory fuzzer. Workers now use non-blocking queue retrieval and always mark dequeued tasks complete; per-item failures no longer silently terminate a worker.
- Add deterministic regression coverage for concurrent queue draining and guard all four recon modules against reintroducing the unsafe empty-then-get pattern.

## 2026-10-10

- Fix the network mapper's documented full IPv4 range syntax while retaining the existing last-octet shorthand. Reject descending or mixed-IP-version ranges with explicit errors.
