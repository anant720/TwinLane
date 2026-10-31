# ADR 0005: Transport Abstraction (In-Process vs. HTTP / JSON-RPC)

**Status**: Accepted  
**Date**: 2026-10-31  
**Authors**: Anant, Shweta, Aditya  

---

## Context
TwinLane must support two core deployment modes:
1. **High-Throughput Local Benchmarking and Testing**: Running thousands of randomized adversarial attack iterations in test suites and evaluation harnesses without network socket overhead, port binding conflicts, or OS socket exhaustion.
2. **Distributed Inter-Agent Networking**: Production communication between independent agents deployed across separate servers, Docker containers, or cloud environments.

## Decision
We chose a **pluggable Transport Abstraction Layer** with two concrete implementations:
1. `InProcTransport`: Memory-based queue transport for high-speed automated benchmarking and testing.
2. `HttpTransport`: Asynchronous HTTP/1.1 and HTTP/2 transport built on `httpx` and `fastapi` for distributed deployments.

### Rationale
1. **Identical Security Enforcement**:
   - Both transports operate on identical canonicalized JSON wire envelopes and invoke the identical Gate pipeline.
   - The security guarantees (P1–P5) are independent of the transport medium.
2. **Benchmark Determinism**:
   - `InProcTransport` enables running 1,000+ benchmark trials in seconds with zero network jitter or connection drops, ensuring rigorous, reproducible measurements of Gate CPU time and latency.
3. **Standards-Compliant Network Interoperability**:
   - `HttpTransport` maps TwinLane envelopes to standard HTTP `POST /api/v1/twinlane/envelope` endpoints with `Content-Type: application/json`.
   - Allows seamless integration with API gateways, load balancers, and external agent frameworks (e.g., LangGraph, AutoGen, CrewAI).

## Consequences
- **Positive**: Clean separation of protocol concerns from networking; instant local testing; production-ready HTTP transport.
- **Negative**: Requires maintaining two transport classes, though both share a simple abstract base class (`Transport`).
