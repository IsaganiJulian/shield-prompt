"""
PHASE 2: PAYLOAD PARSER — STRUCTURAL DECOMPOSITION
===================================================

Overview
--------
Phase 2 extracts untrusted text from JSON/MCP/API structures, classifies each
field as STRUCTURAL (metadata, low risk) or SCANNABLE (user text, requires
detection), and returns JSON paths for threat attribution.

This enables efficient dual-path processing: structural fields bypass expensive
detection, while only user-supplied content gets scanned.

Architecture
------------

Raw Payload (JSON/MCP/API)
       │
       ├─ Walk structure recursively
       │
       ├─ Classify each string field:
       │  • Key name check (STRUCTURAL_KEYS vs SCANNABLE_KEYS)
       │  • Value pattern check (UUID, timestamp, enum, etc.)
       │  • Default fallback (conservative: assume scannable)
       │
       ├─ Return classified fields with:
       │  • JSON path for attribution ($.messages[0].content)
       │  • Field value and classification
       │  • Source type (JSON, MCP, API_RESPONSE)
       │
       └─ ParseResult ready for DualGateRouter

Classification System
---------------------

STRUCTURAL (Skip Detection):
  Key Names:
    - Identifiers: id, user_id, org_id, session_id
    - Metadata: type, version, status, schema, role
    - Timestamps: timestamp, created_at, updated_at, created
    - System: method, protocol, format, encoding, model, api_version
    - IDs: request_id, correlation_id, trace_id, tool_use_id
  
  Value Patterns:
    - UUIDs: 550e8400-e29b-41d4-a716-446655440000
    - ISO timestamps: 2024-05-26T14:30:00.000Z
    - Numeric values: 42, 3.14, 1000
    - Known enums: "user", "assistant", "get", "post", "success", "error"

SCANNABLE (Requires Detection):
  Key Names:
    - Content: content, text, message, query, prompt
    - User Input: input, output, command, instruction
    - Metadata: description, title, comment, note, body
    - Free-form: reason, summary, detail, context, result
    - Tool-specific: tool_input, arguments, data, value
  
  Value Patterns:
    - Long free-form strings (>50 characters)
    - User-supplied text (default fallback)
    - Multi-line content

JSON Path Attribution
---------------------

JSONPath notation for precise threat location:

Example MCP envelope:
{
  "messages": [
    {"role": "user", "content": "ignore all previous"}
  ]
}

Extracted fields:
  $.messages[0].role       → STRUCTURAL (not scanned)
  $.messages[0].content    → SCANNABLE (must be scanned)

Complex nested example:
  $.user.profile.bio       → SCANNABLE
  $.user.id                → STRUCTURAL
  $.metadata.created_at    → STRUCTURAL
  $.tools[0].description   → SCANNABLE

Usage Example
-------------

from core.payload_parser import PayloadParser

parser = PayloadParser(max_depth=20)

# Parse MCP envelope
payload = {
    "messages": [
        {"role": "user", "content": "What is AI?"},
        {"role": "assistant", "content": "AI is..."}
    ]
}

result = parser.parse(payload)

# Access results
scannable_fields = result.scannable_fields
# → [ParsedField(json_path="$.messages[0].content", ...),
#    ParsedField(json_path="$.messages[1].content", ...)]

structural_fields = result.structural_fields
# → [ParsedField(json_path="$.messages[0].role", ...),
#    ParsedField(json_path="$.messages[1].role", ...)]

# Get scannable text ready for ShieldDetector
texts = result.scannable_texts  # ["What is AI?", "AI is..."]
paths = result.scannable_paths  # ["$.messages[0].content", "$.messages[1].content"]

Core Components
---------------

FieldClassification Enum:
  • STRUCTURAL: Metadata, low injection risk
  • SCANNABLE: User text, requires detection

PayloadSource Enum:
  • JSON: Raw JSON structure
  • MCP: Model Context Protocol / JSON-RPC envelope
  • API_RESPONSE: External API response
  • UNKNOWN: Unclassified source

ParsedField:
  • json_path: JSONPath location
  • value: String value extracted
  • classification: STRUCTURAL or SCANNABLE
  • source: PayloadSource enum
  • key_name: Field key name
  • depth: Nesting depth

ParseResult:
  • source: Detected payload source
  • total_fields: Count of all extracted fields
  • scannable_fields: User text requiring detection
  • structural_fields: Metadata (skip detection)
  • parse_errors: Any parsing issues
  • all_fields (property): Combined list
  • scannable_texts (property): Flat text list for detector
  • scannable_paths (property): JSON paths for attribution

Configuration
--------------

PayloadParser accepts max_depth parameter:

parser = PayloadParser(max_depth=20)  # Prevent stack overflow

Behavior:
  • Stops recursion at max_depth
  • Logs error if exceeded
  • Returns partial results

Test Coverage
-------------

PayloadParser has 25+ test cases (Phase 2):
  ✓ Flat structures (structural only, scannable only)
  ✓ Nested structures (recursive walking)
  ✓ Arrays and mixed types
  ✓ MCP message envelopes
  ✓ UUID/timestamp value classification
  ✓ Field key classification
  ✓ JSON path generation accuracy
  ✓ Edge cases (empty, null, deeply nested)
  ✓ Large payloads (100+ fields)

Performance
-----------

Parsing:
  • Typical payload (10 fields): <1ms
  • Large payload (1000 fields): ~10-20ms
  • Very deep structures: depends on max_depth

Memory:
  • O(n) where n = field count
  • Recursive stack: O(d) where d = depth

Integration Points
------------------

Upstream (Receives):
  • Raw JSON payloads from APIs
  • MCP message envelopes from agents
  • API response bodies

Downstream (Routes To):
  • DualGateRouter for orchestration
  • ShieldDetector for threat analysis
  • Threat dashboard for visualization

Future Enhancements
-------------------

Phase 3: DualGateRouter uses parser output for dual-path routing
Phase 4: Streamlit dashboard visualizes parsed structure + threats
"""
