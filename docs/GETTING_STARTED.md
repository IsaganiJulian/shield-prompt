"""
GETTING STARTED WITH SHIELDPROMPT
==================================

Quick Setup
-----------

1. Install dependencies
   pip install -r requirements.txt

2. Set up environment
   cp .env.example .env
   # Fill in your API keys (Bright Data, OpenAI, etc.)

3. Run tests to verify installation
   pytest tests/ -v

Using ShieldPrompt
-------------------

Basic Usage (Single Payload):

    from src.core.router import DualGateRouter, RoutingDecision

    # Initialize the security router
    router = DualGateRouter()

    # Route a payload through the detection pipeline
    payload = {"content": "What is machine learning?"}
    result = router.route(payload)

    # Check the security verdict
    if result.decision == RoutingDecision.ALLOW:
        print("Safe to process")
    elif result.decision == RoutingDecision.BLOCK:
        print(f"Request blocked: {result.escalation_reason}")
    elif result.decision == RoutingDecision.ESCALATE:
        print(f"Requires human review: {result.escalation_reason}")

MCP Message Processing:

    # ShieldPrompt is MCP-aware
    mcp_payload = {
        "messages": [
            {"role": "user", "content": user_query},
            {"role": "assistant", "content": agent_response}
        ],
        "model": "claude-3-opus",
    }

    result = router.route(mcp_payload)

    # Each field has a JSON path for precise threat attribution
    for threat in result.critical_threats:
        print(f"Threat at {threat.parsed_field.json_path}")
        print(f"Confidence: {threat.detection_result.confidence:.2f}")

Batch Processing:

    payloads = [
        {"content": "Query 1"},
        {"content": "Query 2"},
        {"content": "Query 3"},
    ]

    results = router.batch_route(payloads)

    for payload, result in zip(payloads, results):
        if result.decision != RoutingDecision.ALLOW:
            print(f"Threat in: {payload}")

Accessing Threat Details:

    result = router.route(suspicious_payload)

    # Get all critical threats
    for threat in result.critical_threats:
        print(f"Location: {threat.parsed_field.json_path}")
        print(f"Value: {threat.parsed_field.value}")
        print(f"Confidence: {threat.detection_result.confidence}")
        print(f"Evidence: {threat.detection_result.evidence}")

    # Generate readable audit report
    print(router.generate_report(result))

Configuration
--------------

Customize detection thresholds:

    from src.core.router import DualGateRouter

    config = {
        "critical_block_threshold": 0.90,  # CRITICAL + 90% → BLOCK
        "escalation_threshold": 0.80,      # HIGH + 80% → ESCALATE
        "auto_remediate": True,            # Enable auto-fix
    }

    router = DualGateRouter(config=config)

Understanding Results
---------------------

RoutingDecision Enum:
  • ALLOW: No threats detected, safe to proceed
  • BLOCK: Critical threat detected, immediate rejection
  • QUARANTINE: Medium threat, mark for review
  • ESCALATE: High-confidence threat, route to human
  • REMEDIATE: Threat auto-fixed by supervisor

Threat Levels:
  • CLEAN: No threat detected (confidence 0.0)
  • LOW: Low-severity threat (0.0-0.5)
  • MEDIUM: Medium threat (0.5-0.75)
  • HIGH: High-severity threat (0.75-0.90)
  • CRITICAL: Critical/immediate threat (0.90+)

Running Tests
-------------

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_router.py -v

# Run specific test
pytest tests/test_router.py::TestDualGateRouter::test_malicious_prompt_detected_in_content_field -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run benchmarks
python tests/evaluate.py

Architecture Overview
---------------------

Phase 1: Multi-Tiered Detection (src/core/shield.py)
  └─ Tier 1: Lexical analysis (regex patterns) ~5-10ms
  └─ Tier 2: Semantic analysis (LLM) ~100-200ms [Placeholder]
  └─ Tier 3: Behavioral analysis [Placeholder]

Phase 2: Payload Parser (src/core/payload_parser.py)
  └─ Extracts fields from JSON/MCP/API structures
  └─ Classifies: STRUCTURAL (skip) vs SCANNABLE (scan)
  └─ Returns JSON paths for threat attribution

Phase 3: Dual-Gate Router (src/core/router.py)
  └─ FAST PATH: Structural fields bypass detection
  └─ COMPREHENSIVE PATH: Scannable fields through Tiers 1-3
  └─ Orchestrates parser → detector → supervisor → decision

See docs/OVERVIEW.md for full architecture.

Troubleshooting
---------------

Import errors?
  - Make sure you're running from the project root
  - Verify src/core/__init__.py exists
  - Check PYTHONPATH includes the project directory

Tests failing?
  - Run: pip install -r requirements.txt
  - Check Python version (3.12+ required)
  - Verify all core modules are in src/core/

Slow performance?
  - Most time spent in Tier 2/3 (LLM analysis)
  - Structural-only payloads are very fast (<2ms)
  - Batch processing is more efficient than individual calls

Common Questions
----------------

Q: Why skip structural fields?
A: Metadata like UUIDs, timestamps, IDs have zero injection risk.
   Skipping them dramatically improves performance while maintaining
   security for user-supplied content.

Q: What's the confidence score?
A: 0.0 (definitely safe) to 1.0 (definitely malicious). Tier 1 uses
   regex (deterministic), Tier 2/3 use ML (probabilistic). Router
   synthesizes final verdict based on confidence + threat level.

Q: How does JSON path attribution help?
A: Precise threat location enables:
   - Forensics (what exactly triggered the alert?)
   - Audit logging (which field was malicious?)
   - Targeted remediation (fix only that field)
   - Dashboard visualization (show threats on payload tree)

Q: Can I use custom detection logic?
A: Yes! Subclass ShieldDetector or extend PayloadParser.
   DualGateRouter is fully injectable.

Next Steps
----------

1. Review architecture: docs/OVERVIEW.md
2. Check phase details: docs/phases/PHASE_*.md
3. Run tests: pytest tests/ -v
4. Try examples above
5. Integrate into your application
6. Monitor logs for threat patterns
7. Contribute improvements!

For more information, see the full documentation in docs/
"""
