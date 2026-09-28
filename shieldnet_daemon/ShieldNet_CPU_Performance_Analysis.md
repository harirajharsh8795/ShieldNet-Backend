# ShieldNet — Daemon CPU Usage: Investigation & Optimization Recommendations
**Addendum to: ShieldNet_NextPhase_Report.md**
**Topic: Observed CPU usage while monitoring a wide port range, and how to actually fix it**

---

## 0. Context

While running the current daemon and monitoring a WiFi interface across a port range in the thousands, observed CPU usage in Task Manager reached ~8–10% on an i9 / 16GB RAM development machine. This document captures the investigation reasoning and the recommended fix path — profiling first, then applying targeted optimizations in priority order.

**Note:** a "cross-node fast-path inference shortcut" idea (using a matched third-party ledger signature to skip local inference/SHAP work) was raised and then deliberately dropped — it wasn't part of any previously agreed design, and the cost it would have addressed (SHAP explanation cost) is already solved by the existing "gate SHAP to flagged windows only" design. This document does not include that idea.

---

## 1. Is 8–10% Actually a Problem?

Before optimizing anything, worth separating perception from an actual constraint:

- On an i9 (likely 8+ cores, 16+ logical threads), 8–10% total utilization is roughly **under one full core** being consumed continuously.
- Real production network monitors (Zeek, Suricata) routinely run hotter than this on always-on traffic inspection — so this number alone is not automatically alarming.
- **The number that actually matters for the pitch is what this looks like on hardware closer to real deployment** — a CII edge box is very unlikely to be an i9. Test on lower-spec hardware before treating this as solved or unsolved.

**Recommendation:** don't optimize blind. Profile first (Section 2), then decide whether the numbers from Section 3 are actually needed, or whether the current performance is already acceptable relative to realistic deployment hardware.

---

## 2. Profile Before Optimizing

Consistent with the project's standing rule against unverified claims — this applies to performance numbers just as much as detection metrics.

- Use **`py-spy`** (sampling profiler, works against a live running process, low overhead) or **`cProfile`** against the daemon during a minute of live traffic.
- Identify which function is actually consuming the time before changing anything.
- Working hypothesis (see Section 3) is that kernel-level filtering is missing and Python is doing per-packet work on traffic that should never reach it — but this is a hypothesis, not a confirmed finding, until profiled.

---

## 3. Likely Cause & Recommended Fixes, In Priority Order

### 3.1 Push filtering down to the kernel via a BPF capture filter (highest leverage, do this first)
- Npcap/libpcap both support BPF-style capture filters — same syntax as Wireshark's capture filters (e.g. `tcp portrange 1000-9000`).
- This means packets outside the range of interest **never reach Python at all** — dropped at the driver level.
- Almost certainly the single biggest available win, since it changes "process N packets in Python" to "process a fraction of N," with zero pipeline redesign.

### 3.2 Batch, don't process per-packet
- If the current loop calls into feature-extraction/Python logic once per packet, that's significant function-call and object-creation overhead multiplied by packet count.
- The existing design already calls for a rolling time-window buffer — confirm it's actually **accumulating packets and only running heavier logic once per window close**, not doing meaningful work on every single packet as it arrives.

### 3.3 Consider `dpkt` over Scapy for raw parsing (only if still hot after 3.1–3.2)
- Scapy is convenient but does more object-oriented work per packet than a lean byte-level parser needs.
- Known, citable optimization path — worth mentioning even if not switched immediately.

### 3.4 Multiprocessing, not threading, if more throughput is genuinely needed
- Python's GIL means threads won't actually parallelize CPU-bound feature extraction.
- If profiling still shows a hot spot after 3.1–3.3, a separate **process** (not thread) for the capture/extraction hot path is the correct lever, communicating results back via a queue.

---

## 4. Recommended Sequence

1. Profile the daemon (`py-spy` or `cProfile`) during live traffic — confirm where time is actually going.
2. Apply the BPF capture filter for the monitored port range — almost certainly the actual bottleneck given the "port range in the thousands" observation.
3. Re-measure CPU usage after the filter is applied.
4. Only pursue `dpkt` migration or multiprocessing if the profile still shows a hot spot after step 2.
5. Separately, test the daemon's CPU usage on lower-spec hardware to get the number that actually matters for the pitch/deployment story.

---

## 5. Task Items Generated From This Discussion

| # | Task | Notes |
|---|---|---|
| 1 | Profile the daemon with `py-spy` or `cProfile` during a live traffic sample | Do this before any optimization — confirms or corrects the hypothesis below |
| 2 | Apply a BPF capture filter scoped to the monitored port range at the Npcap/libpcap level | Highest-leverage fix; packets outside range should never reach Python |
| 3 | Verify the rolling time-window buffer batches work per-window, not per-packet | Confirms design intent is actually implemented as specified |
| 4 | Re-measure CPU usage after the BPF filter is applied | Confirms the fix actually worked before considering further optimization |
| 5 | Test daemon CPU usage on lower-spec hardware (closer to realistic CII edge deployment) | The i9/16GB number is not the number that matters for the pitch |
| 6 | (Only if still hot after above) Evaluate `dpkt` as a Scapy replacement for raw packet parsing | Lower-level, faster parser; known optimization path |
| 7 | (Only if still hot after above) Move capture/extraction hot path to a separate process, not thread | GIL means threads won't parallelize CPU-bound work |
