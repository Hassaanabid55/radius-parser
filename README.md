# Radius Parser

High-performance multithreaded RADIUS accounting packet parser built for telecom-grade traffic processing.

## Architecture Highlights

- libpcap-based live packet capture
- pthread worker pool architecture
- Lock-protected task queue
- In-memory O(1) CGNAT + Whitelist lookup
- MySQL + File-based hybrid data source
- **Live reload system via UNIX socket (no polling)**
- Modular design (DB, CGNAT, Whitelist, Parser, Worker)

---

## Features

- Live RADIUS Accounting packet capture
- Multithreaded worker processing
- Session extraction & attribute parsing
- CGNAT resolution (private IP + port → public IP)
- Whitelist MSISDN validation
- O(1) hashmap-based lookups
- Dynamic runtime reload of:
  - CGNAT table
  - Whitelist table
- Supports both:
  - MySQL database source
  - CSV / file-based source fallback
- Zero-downtime configuration updates

---

## Build Dependencies

Install required dependencies:

```bash
./scripts/install_deps.sh