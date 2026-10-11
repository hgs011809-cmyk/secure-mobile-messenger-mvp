# Actual loopback TCP transport evidence

Local Node22:8 network cases passed after explicitly waiting for server-side socket close observers as well as client closes; all listeners/sockets zero and disposable namespace removed. Real127.0.0.1 TCP/HTTP listener on an ephemeral port, synthetic memory-only capability and immutable supplied binding. NOT Internet/Android/Matrix authenticated transfer.

8 MiB complete-file AES-256-CTR ciphertext,256 KiB chunks: two half-body drops, two lost acknowledgements and receiver/listener reconstructions during full transfer; final whole SHA matches the independently trusted manifest after reading all32 persisted chunks. Same-length corruption rejected after completion. Partial body never committed; accepted-before-ack retry idempotent. Missing capability and changed/revoked supplied binding rejected. Advertised/chunked oversized bodies rejected before receiver persistence.

The8 MiB fixture is fully buffered for test generation; it does not establish streaming encryption or memory/RSS bounds. Parser-payload counter is not total memory. Capability is test-only over loopback HTTP, not user authentication or production TLS/E2EE. Callback binding and root ownership remain fixture assumptions. Source/API quotas, epoch ABA, physical deletion, OS crash, backups, browser/Android, public ingress and product throughput remain unverified.

Initial6 network failures and nested/VM loader failures are preserved in RUNTIME_NOTES.md. No failure was treated as a success because HTTP replies were200. Final combined Linux74/74 passed in run38140155348/338c84f; independently inspected aggregates and private cleanup. New standalone tone HTML is not covered by this CI.
