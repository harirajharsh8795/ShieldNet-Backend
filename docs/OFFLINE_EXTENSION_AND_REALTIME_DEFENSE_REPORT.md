# ShieldNet Offline Downloadable Defense Application

## Purpose

This report describes how ShieldNet can become a downloadable, offline-capable desktop application for Windows, Linux, and macOS systems. The application would monitor traffic arriving at the protected system, detect suspicious activity with the existing ShieldNet inference and explainability pipeline, immediately alert the operator, persist the incident in MySQL, and request host-firewall enforcement for the malicious source.

This is an implementation design only. No application code is changed by this report.

## Important Scope Boundary

The current repository contains an offline Streamlit dashboard, a FastAPI backend, model inference, explainability, SIERL evidence/ledger code, SQLite persistence, and a simulated firewall orchestrator. The current `src/ledger/orchestrator.py` generates `iptables`/`nftables` rules in an execution record; it does not execute operating-system firewall commands. The current live sniffer also includes simulation/replay behavior when packet-capture privileges or drivers are unavailable.

Therefore, production protection requires three additions around the existing code:

1. A real packet/flow capture service with OS-specific permissions and a clear degraded mode.
2. A privileged, narrowly scoped firewall helper that validates and applies deny rules.
3. A durable local database and alert/event pipeline that cannot depend on an internet connection.

The browser UI or dashboard must never be treated as the security boundary. If the UI closes, the capture, detection, database, alert, and blocking services must continue running.

## Recommended Product Shape

### Downloadable desktop application, not a browser-only extension

A normal browser extension cannot reliably inspect all traffic arriving at an operating system or permanently block an IP at the host firewall. Browser extensions are restricted to browser requests and browser permissions. The suitable product is a **downloadable desktop security agent** with a local dashboard.

Recommended package:

- A background ShieldNet agent installed as an operating-system service.
- A local API bound to `127.0.0.1` only.
- A local dashboard opened in the default browser, or the existing React/Vite frontend packaged in a desktop shell.
- A separate privileged helper for firewall changes.
- An optional local MySQL/MariaDB service or a connection to an already approved MySQL server.

The phone requirement is intentionally excluded. Android and iOS require a separate mobile architecture and do not provide equivalent unrestricted host-firewall control to a desktop security agent.

## Technology Selection Aligned With This Repository

| Area | Recommendation | Reason it fits ShieldNet |
|---|---|---|
| Inference | PyTorch CPU runtime, existing world model and calibrated models | Reuses `src/world_model`, existing checkpoints, and offline inference |
| API/control plane | FastAPI + Uvicorn on loopback | Already used by `src/api/server.py`; provides local health, prediction, incident, explanation, and control endpoints |
| Dashboard | Existing Streamlit dashboard for the first desktop release; React/Vite in a later desktop shell | Minimizes first-release change while preserving the repository's existing UI options |
| Desktop packaging | PyInstaller or Nuitka for the Python agent; optional Tauri shell for React/Vite | Produces downloadable Windows/Linux/macOS installers without requiring Python or Node on the target machine |
| Packet capture | Npcap on Windows; libpcap on Linux/macOS; Scapy or a maintained flow extractor | Matches the existing live-sniffer direction and supports real interfaces offline |
| Flow features | Existing 84-feature schema, sequencer, scaler guard, OOD detector | Keeps model inputs compatible with current checkpoints and validation safeguards |
| Explainability | Existing Captum/dual-engine explainer and MITRE reasoner | Provides feature drivers, attack class, stage, and plain-language reasoning locally |
| Enforcement | Windows Filtering Platform/Windows Firewall helper; Linux nftables; macOS Packet Filter (`pf`) | Applies blocking at the host boundary rather than only inside the UI |
| Persistence | SQLAlchemy with `mysql+pymysql` or `mysql+mysqlconnector`; Alembic migrations | Extends the existing `src/database/db.py` abstraction while retaining SQLite for demo/fallback mode |
| Evidence integrity | Existing SHA-256 hashing and SIERL ledger | Binds raw evidence, model, prediction, explanation, and mitigation records |
| Notifications | Native desktop notifications plus local audible/visual alert; optional email/webhook only when explicitly configured | Works with zero internet access and does not make cloud delivery a prerequisite |
| Installer/update signing | MSIX or signed MSI on Windows; signed DMG/PKG on macOS; AppImage/deb/rpm on Linux | Gives users a downloadable and verifiable distribution channel |

## Target Runtime Architecture

```text
Incoming packets
      |
      v
Capture service (Npcap/libpcap, least privilege)
      |
      v
Flow aggregation and 10-second windowing
      |
      v
Existing feature adapter -> frozen scaler -> OOD guard
      |
      v
World Model + tabular ensemble
      |
      +--> mandatory XAI + MITRE explanation
      |
      +--> risk policy and confidence gate
      |          |
      |          +--> local alert event
      |          +--> incident/evidence write to MySQL
      |          +--> SIERL evidence/decision record
      |          +--> privileged firewall helper
      |
      +--> loopback FastAPI API -> dashboard

Privileged helper -> OS firewall -> durable local deny rule
```

The capture service, inference service, alert service, and database writer should run as supervised background components. The dashboard is a client of the local API and is not responsible for packet capture or enforcement.

## Real-Time Detection and Immediate Alert Flow

1. The agent starts with the operating system and verifies the model, scaler, feature manifest, policy, and database connection.
2. The capture adapter reads packets or flow records from the selected physical interface. It must identify source IP, destination IP, ports, protocol, timestamps, direction, and enough packet/flow statistics to construct the existing feature vector.
3. A bounded flow table aggregates packets into the configured 10-second windows. The agent must use back-pressure and eviction limits so an attack cannot exhaust memory.
4. The existing schema adapter, frozen scaler guard, OOD detector, world model, and secondary classifier produce a prediction. The agent should preserve the model's calibrated probabilities and record the model/checkpoint hash.
5. The mandatory explanation gate runs before a block decision. The incident is not promoted to automatic enforcement if the explanation is missing, the input is out of distribution beyond policy limits, or the model assets fail integrity checks.
6. A policy engine evaluates confidence, severity, attack class, source address validity, allowlists, local network role, and repeated-observation requirements. A high-confidence attack can generate an immediate alert and block request; lower-confidence events can alert and observe.
7. The alert event is emitted locally before or in parallel with enforcement. The alert should include source IP, first/last seen time, severity, confidence, attack class, MITRE stage/tactic, top contributing features, plain-language explanation, evidence ID, and enforcement status.
8. The incident, source address, explanation, evidence hashes, policy decision, and helper result are committed to MySQL in one transaction where possible. A local durable queue is required if MySQL is temporarily unavailable.
9. The privileged helper validates the request and inserts the deny rule into the correct OS firewall set. It returns an execution ID and actual rule identifier, not only a generated command string.
10. The dashboard receives the event through local WebSocket or Server-Sent Events and displays it immediately. The same alert remains visible after restart because it is read from MySQL.

For a practical target, measure separately: packet-to-feature time, feature-to-prediction time, prediction-to-alert time, database commit time, and firewall enforcement time. Do not advertise a single “instant” number until those measurements are taken on each supported operating system.

## Blocking Design and the Meaning of “Permanent”

The requested permanent block should mean **persistent until an authorized administrator removes it**, not an irreversible operation. Irreversible blocking can lock out legitimate administrators, block shared/cloud/NAT addresses, and create a denial-of-service condition.

### Required denylist record

Each deny entry should contain:

- A normalized IPv4 or IPv6 address or CIDR range.
- Scope: ingress, egress, interface, VLAN, or host-wide.
- Reason and incident ID.
- Detection confidence and attack classification.
- Created time, last observed time, and actor/policy that created it.
- Status: `ACTIVE`, `REMOVAL_PENDING`, `REMOVED`, or `FAILED`.
- OS, firewall backend, rule identifier, and helper execution ID.
- Optional expiry/review timestamp, even when the default policy is indefinite.

### Safety controls

- Reject malformed, multicast, broadcast, loopback, link-local, and protected allowlist addresses unless an explicit administrative policy permits them.
- Support IPv6 as well as IPv4.
- Do not automatically convert a single suspicious source into a broad CIDR block.
- Protect management addresses, local gateway addresses, DNS/NTP infrastructure, and approved monitoring systems with an allowlist.
- Require a separate authenticated action to remove a persistent rule.
- Make the first release default to “alert plus block” only above a documented confidence/severity threshold.
- Use idempotent rules so repeated detections do not create duplicate firewall entries.
- Record failed enforcement and show it as a security incident; never report a block as successful because a command was merely generated.
- Provide an offline recovery command or administrator console path to remove a rule if the dashboard is unavailable.

### OS enforcement approach

- **Windows:** use a signed Windows service/helper and Windows Filtering Platform or Windows Defender Firewall APIs. PowerShell/`netsh` may be used for diagnostics, but production enforcement should use validated API calls where practical. The service requires an explicit administrator installation step.
- **Linux:** use nftables sets with stable element identifiers and an atomic set update. Support iptables only as a compatibility fallback. The agent requires root or a narrowly scoped systemd helper policy.
- **macOS:** use a signed privileged helper and Packet Filter anchors or an approved Network Extension architecture. Do not assume that Linux commands exist on macOS.

The helper should accept structured input such as `{address, direction, reason, incident_id}` rather than arbitrary shell commands. It should validate address syntax, escape all values, use allowlisted operations, and return a verifiable result.

## MySQL Database Design

MySQL should be the system of record for operational incidents and denylist state. The SIERL ledger can continue to provide tamper-evident evidence linkage; it should not replace relational queries needed by the dashboard and policy engine.

Recommended tables:

### `incidents`

Stores one detection event: `incident_id`, timestamps, source/destination addresses, ports, protocol, attack class, severity, confidence, MITRE stage/tactic, model hash, prediction hash, explanation hash, OOD status, policy decision, and current status.

### `network_observations`

Stores the normalized flow/window metadata and selected feature values needed for investigation. Raw packet payloads should not be stored by default; store an evidence path and SHA-256 hash when packet capture is retained.

### `explanations`

Stores the plain-language narrative, top feature attributions, attention/trajectory summary, explanation engine version, and hash. Keep a JSON column for the complete structured explanation plus indexed columns for common filters.

### `denylist_entries`

Stores normalized source address/CIDR, scope, status, reason, incident link, OS backend, firewall rule ID, created/removed times, and policy version. Add a uniqueness constraint over active address plus scope to make enforcement idempotent.

### `enforcement_events`

Stores each helper request and result, including request hash, execution ID, OS, backend, result code, stderr-safe diagnostic, and actual rule identifier.

### `evidence_records`

Retains the existing evidence concept: filename, type, size, location, hash, associated incident, and SIERL block hash.

### `audit_events`

Stores login, policy changes, manual approvals, denylist removals, model changes, and recovery actions. Audit records should be append-only for the application role.

The existing SQLAlchemy models and `DATABASE_URL` mechanism are a good starting point. The production connection string should use a MySQL dialect, connection pooling, TLS when connecting to a separate server, least-privilege credentials, and Alembic migrations. Do not hard-code database credentials in the installer or repository.

## Offline-First Database Operation

There are two supported deployment modes:

1. **Single-system mode:** install MySQL Community Server or MariaDB locally and bind it to localhost. The ShieldNet agent, database, and dashboard all operate without internet access.
2. **Enterprise mode:** connect to an approved internal MySQL server while retaining a local SQLite or append-only event queue for outages. Events are assigned stable IDs and replayed idempotently after reconnection.

The installer should optionally bundle a database prerequisite or provide a documented pre-install step. Bundling a database server increases package size, patching responsibility, service-management complexity, and backup requirements. For the first release, a separate approved MySQL/MariaDB installer is operationally simpler; the agent should fail clearly if the required schema is unavailable rather than silently discarding incidents.

## Alert and Explanation Content

Every automatic alert should be understandable without opening a notebook or reading model output. The local notification and dashboard detail should show:

```text
ShieldNet blocked 203.0.113.10

Why: repeated inbound SYN activity and abnormal connection timing matched a
high-confidence PortScan pattern.
Risk: HIGH | Confidence: 96.4% | MITRE: Reconnaissance (TA0043)
Observed: interface Ethernet | first seen 14:03:11 | last seen 14:03:16
Evidence: INC-... | Firewall result: ACTIVE
Top drivers: syn_ratio, destination-port spread, flow inter-arrival variance
Action: persistent host deny rule created; administrator removal required
```

The exact narrative must be generated from measured features and the symbolic reasoner, not from an invented IP reputation claim. The system should say “ShieldNet observed...” rather than assert attribution to a person or organization unless external evidence is available and explicitly configured.

## Download and Installation Experience

### Windows first release

- Build a signed installer using MSIX or MSI.
- Install the unprivileged agent/dashboard service and a separate signed elevated helper.
- Install or detect Npcap in compatible capture mode.
- Register the agent as a Windows Service with automatic restart.
- Open a local onboarding page at `http://127.0.0.1:<port>` after installation.
- Ask the administrator to select the capture interface, protected networks, allowlist, database mode, and enforcement policy.
- Verify model hashes, capture capability, firewall helper connectivity, database schema, and a test alert before declaring the system ready.

### Linux and macOS packages

- Linux: provide deb/rpm and optionally AppImage, plus a systemd unit and a narrowly scoped privileged helper.
- macOS: provide signed/notarized PKG/DMG and the required system/network extension permissions.
- Publish SHA-256 checksums and signature verification instructions with every release.

The release bundle must include model checkpoints, feature manifests, frozen scaler/reference statistics, MITRE mapping data, migration files, frontend assets, and an offline license/notice directory for dependencies. No first-run download should be required.

## Security and Privacy Requirements

- Bind the local API to loopback by default; require explicit configuration before LAN access.
- Use the repository's authentication/RBAC concepts for administrator, analyst, and auditor roles.
- Protect local API actions against CSRF and unauthorized local processes where the platform permits it.
- Store secrets in the OS credential store or a protected service configuration, not in frontend code.
- Encrypt MySQL connections when MySQL is not local.
- Restrict raw PCAP retention, redact payloads where possible, and configure retention/deletion policies.
- Sign model artifacts and verify hashes at startup and before automatic enforcement.
- Never execute arbitrary rule text received from the UI or database.
- Log clock source and timezone consistently in UTC.
- Test behavior when the database, model, capture driver, helper, disk, or dashboard is unavailable.

## Implementation Phases

### Phase 1: Production contract and local service boundary

- Define the incident, denylist, explanation, enforcement, and audit schemas.
- Add an explicit agent lifecycle and health model.
- Separate simulated firewall output from real enforcement status.
- Define policy thresholds, allowlists, review rules, and recovery procedures.

### Phase 2: Real capture and detection stream

- Integrate Npcap/libpcap capture adapters.
- Replace synthetic fallback with an explicit `SIMULATION` mode that cannot claim protection.
- Connect capture windows to the existing preprocessing, inference, OOD, and explanation path.
- Add bounded queues, back-pressure, metrics, and restart recovery.

### Phase 3: MySQL persistence and offline queue

- Add MySQL SQLAlchemy configuration and migrations.
- Persist incident and enforcement records transactionally.
- Add local durable replay for database outages and idempotency keys.
- Add backup/restore and retention procedures.

### Phase 4: Privileged enforcement helper

- Implement a separate helper for each supported OS.
- Validate structured requests, apply idempotent rules, and return actual rule state.
- Add allowlist, IPv4/IPv6, duplicate, rollback, and failure handling.
- Run end-to-end tests in isolated virtual machines.

### Phase 5: Installer and operational hardening

- Build signed installers and package all offline assets.
- Register services, permissions, upgrades, logs, and uninstall cleanup.
- Add tamper tests, crash recovery tests, performance tests, and operator documentation.
- Run a staged pilot in alert-only mode before enabling automatic blocking.

## Verification and Acceptance Criteria

The feature should not be considered complete until the following are demonstrated on every supported OS:

- A real inbound test flow is captured from the selected physical interface.
- The flow is transformed into the expected feature schema without synthetic values.
- A known test attack produces an alert with source address, severity, confidence, MITRE mapping, top drivers, and a plain-language explanation.
- The alert is visible while the dashboard is open and remains in MySQL after agent/dashboard restart.
- A valid high-confidence event creates exactly one active denylist entry and exactly one corresponding firewall rule.
- Repeated detections are idempotent and do not create duplicate rules.
- A malformed, allowlisted, loopback, or protected address is rejected and audited.
- The application reports `BLOCK_FAILED` when the helper lacks privilege or the firewall rejects the rule.
- A machine reboot preserves the intended persistent block and the database record.
- Authorized removal updates MySQL, the audit log, and the actual firewall state.
- The application continues detection and queues incidents when MySQL is temporarily unavailable.
- The system produces no false claim of live protection while running in simulation/replay mode.
- Model, explanation, ledger, and firewall events can be correlated by stable incident and execution IDs.

## Final Recommendation

Build ShieldNet as a signed desktop security agent with a local FastAPI control plane and dashboard, not as a browser-only extension. Keep PyTorch, the existing feature/schema guards, dual-engine explanation, MITRE reasoner, SIERL hashing, and SQLAlchemy. Add real capture adapters, a MySQL-backed incident/denylist schema, an offline event queue, and OS-specific privileged helpers. Treat persistent blocking as an audited administrator-removable policy, and make every alert explain what was observed, why it was classified as malicious, what was blocked, and whether the firewall actually confirmed enforcement.
