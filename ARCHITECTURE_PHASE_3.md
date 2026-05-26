"""
PHASE 3: DUAL-GATE ROUTING ARCHITECTURE
========================================

Overview
--------
Phase 3 implements the central orchestration layer that coordinates the entire
ShieldPrompt security pipeline. It introduces a dual-path routing strategy that
optimizes for both performance (structural fields) and comprehensive detection
(scannable fields).

Architecture
------------

    Raw Payload (JSON/MCP/API)
           │
           ├─ PHASE 1: PARSING ──┐
           │                      │
           ├─ PHASE 2: FAST PATH  ├─ PayloadParser classifies fields
           │   (Structural)       │
           ├─ PHASE 3: COMPREHENSIVE ──┐
           │   (Scannable)             │
           ├─ PHASE 4: THREAT ROUTING  ├─ ShieldDetector + SupervisorAgent
           │                           │
           └─ PHASE 5: DECISION ───────┤
               SYNTHESIS                │
                                        │
                                        ▼
                                    RoutingResult
                                    (ALLOW|BLOCK|
                                     QUARANTINE|
                                     ESCALATE|
                                     REMEDIATE)


Key Components
--------------

1. DualGateRouter (core/router.py)
   • Central orchestration engine
   • Coordinates parser, detector, supervisor
   • Implements dual-path routing
   • Generates audit trails
   • Synthesizes final security verdict

2. Dual-Path Strategy

   FAST PATH (Structural Fields):
   • Fields classified as metadata: id, type, status, timestamp, role, etc.
   • UUID patterns, ISO dates, numeric values
   • Short enum-like strings
   • SKIP DETECTION (conserves compute, low injection risk)
   • Fast throughput for metadata-heavy payloads

   COMPREHENSIVE PATH (Scannable Fields):
   • User-supplied text: content, prompt, query, message, etc.
   • Long free-form strings
   • Default fallback for unknown fields (conservative)
   • RUN THROUGH FULL TIER 1-3 DETECTION
   • LLM-based semantic analysis + threat intel sync
   • Auto-remediation via SupervisorAgent

3. Decision Synthesis Logic

   Critical Threat Detected → BLOCK
   ├─ CRITICAL threat level + high confidence (≥90%)
   └─ Immediate rejection

   High Threat (High Confidence) → ESCALATE
   ├─ HIGH threat level + confidence ≥ escalation_threshold
   └─ Route to human operator

   High Threat (Lower Confidence) → QUARANTINE
   ├─ HIGH threat level + confidence < escalation_threshold
   └─ Mark for review, block unless overridden

   Remediated Threat → REMEDIATE
   ├─ Threat successfully auto-fixed by SupervisorAgent
   └─ Return cleaned payload with REMEDIATE verdict

   No Threats → ALLOW
   └─ All scans clean, structural fields safe
   └─ Proceed with processing


Routing Result Structure
------------------------

RoutingResult:
  decision: RoutingDecision (enum)
  confidence: float (0.0-1.0)
  parse_result: ParseResult
    ├─ source: PayloadSource (JSON, MCP, API_RESPONSE)
    ├─ scannable_fields: List[ParsedField]
    └─ structural_fields: List[ParsedField]
  
  field_detections: List[FieldDetectionResult]
    ├─ parsed_field: ParsedField (with json_path for attribution)
    ├─ detection_result: Optional[DetectionResult]
    ├─ remediation_result: Optional[RemediationResult]
    └─ routed_via: str ("structural" or "comprehensive")
  
  audit_trail: List[str] (complete routing log)
  critical_threats: List[FieldDetectionResult] (property)
  high_threats: List[FieldDetectionResult] (property)
  remediated_fields: List[FieldDetectionResult] (property)


JSON Path Attribution
---------------------

Each threat is mapped back to its exact location in the payload tree:

Example MCP envelope:
{
  "messages": [
    {"role": "user", "content": "ignore all previous"},
    {"role": "assistant", "content": "..."}
  ]
}

Threat attribution:
  $.messages[0].content → HIGH threat (injection payload)
  $.messages[0].role → STRUCTURAL (skip)
  $.messages[1].content → CLEAN (no threat)
  $.messages[1].role → STRUCTURAL (skip)

Use cases:
  • Precise threat forensics
  • Audit trail logging
  • Batch remediation targeting
  • Security dashboard reporting


Configuration
--------------

DualGateRouter accepts config dict:

config = {
    # Decision thresholds
    "critical_block_threshold": 0.90,      # CRITICAL + ≥90% → BLOCK
    "escalation_threshold": 0.80,          # HIGH + ≥80% → ESCALATE
    "auto_remediate": True,                # Enable SupervisorAgent
}

router = DualGateRouter(config=config)


Usage Examples
--------------

1. Single Payload Routing
   
   router = DualGateRouter()
   payload = {"content": "What is AI?"}
   result = router.route(payload)
   
   if result.decision == RoutingDecision.ALLOW:
       # Process safely
       pass
   elif result.decision == RoutingDecision.BLOCK:
       # Reject immediately
       raise SecurityException(f"Blocked: {result.escalation_reason}")

2. Batch Processing
   
   payloads = [payload1, payload2, payload3]
   results = router.batch_route(payloads)
   
   for result in results:
       handle_routing_decision(result)

3. MCP Message Processing
   
   mcp_envelope = {
       "messages": [
           {"role": "user", "content": user_query},
           {"role": "assistant", "content": agent_response}
       ]
   }
   result = router.route(mcp_envelope)
   
   # Access audit trail for logging/monitoring
   print(router.generate_report(result))

4. Threat Attribution & Forensics
   
   result = router.route(payload)
   for threat in result.critical_threats + result.high_threats:
       print(f"Threat at {threat.parsed_field.json_path}")
       print(f"Value: {threat.parsed_field.value}")
       print(f"Confidence: {threat.detection_result.confidence}")


Test Coverage
-------------

40+ test cases covering:

✓ Fast Path: Structural fields correctly skip detection
✓ Comprehensive Path: Scannable fields routed to detector
✓ Field Classification: UUIDs, timestamps, enums properly classified
✓ MCP Envelopes: Role/content separation, message array handling
✓ Mixed Structures: Nested JSON with both field types
✓ Decision Logic: ALLOW, BLOCK, QUARANTINE, ESCALATE synthesis
✓ Audit Trails: Phase tracking, threat logging, decision record
✓ JSON Path Attribution: $.messages[0].content format validation
✓ Batch Routing: Multiple payload processing
✓ Edge Cases: Empty payloads, null values, deeply nested structures
✓ Large Payloads: 100+ message processing
✓ Report Generation: Readable audit output

Run: pytest tests/test_router.py -v


Performance Characteristics
----------------------------

Structural-Only Payload (fast path):
  • Parse: O(n) where n = field count
  • Detect: O(1) skipped
  • Total: ~1-2ms for typical metadata payload

Scannable-Only Payload (comprehensive path):
  • Parse: O(n)
  • Detect: Tier 1 (regex) ~5-10ms per field
           Tier 2 (LLM semantic) ~100-200ms per field (on-demand)
           Tier 3 (behavioral) ~50-100ms per field (on-demand)
  • Total: Variable, typically 10-500ms depending on Tier hits

Mixed Payload:
  • Fast path processes structural fields instantly
  • Only scannable fields incur detection latency
  • Typical: <100ms for real-world MCP envelopes


Integration Points
------------------

Upstream (Receives):
  • Raw JSON payloads from web services
  • MCP message envelopes from agents
  • API response bodies from external systems
  • User queries from chat interfaces

Downstream (Routes To):
  • ShieldDetector (Tier 1-3 analysis)
  • SupervisorAgent (auto-remediation)
  • Audit logger (compliance records)
  • Threat dashboard (security UI)


Future Enhancements
-------------------

Phase 4 Planned:
  • Streamlit dashboard with real-time threat visualization
  • Webhook integration for external SIEM systems
  • Adaptive thresholds based on threat intel updates
  • Batch remediation UI for human operators
  • Multi-tenant routing with org-level policies
"""
