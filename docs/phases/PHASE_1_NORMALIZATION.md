"""
PHASE 1: INPUT NORMALIZATION PIPELINE
======================================

Overview
--------
Phase 1 implements deterministic input preprocessing to standardize and denormalize
obfuscated payloads before they enter the detection pipeline. This anti-semantic-drift
layer handles Unicode normalization, layered encoding detection, and whitespace
collapse to defeat common evasion techniques.

Purpose
-------
Attackers use encoding tricks to evade pattern matching:
  • Base64 wrapping: encode payload to bypass regex
  • Unicode homoglyphs: substitute similar-looking characters
  • Whitespace obfuscation: add spaces to break pattern matches
  • Nested encoding: Layer multiple encodings to confuse analysis

Phase 1 reverses these tricks to expose the underlying threat.

Architecture
------------

Raw Input (potentially obfuscated)
       │
       ├─ Encoding Detection & Decoding
       │  └─ Base64, Hex, URL-encoding, nested combinations
       │
       ├─ Unicode Normalization (NFKD)
       │  └─ Homoglyph substitution → canonical form
       │
       ├─ Whitespace Collapse
       │  └─ Multiple spaces/tabs → single space
       │
       ├─ Code Block Extraction
       │  └─ Fenced/inline code → separate for analysis
       │
       └─ Normalized Output + Metadata
          └─ Ready for Phase 2 parsing and Phase 3 detection

Key Features
------------

1. Encoding Detection & Decoding
   Automatically detects and reverses:
   • Base64 (RFC 4648 standard)
   • Hexadecimal encoding
   • URL encoding (%XX format)
   • Nested combinations (Base64(Hex(...)))
   
   Max depth: 3 layers (prevents DoS via infinite nesting)
   Timeout: 100ms per input (prevents hangups)

2. Unicode Normalization
   Handles homoglyph attacks:
   • Cyrillic lookalikes: А (Cyrillic A) → A (Latin A)
   • Mathematical operators: ﬁ (ligature) → fi
   • Direction overrides: Removes bidi manipulation characters
   • Zero-width characters: Removes invisible joiners/spaces
   
   Uses NFKD normalization for canonical comparison

3. Whitespace Collapse
   Prevents pattern evasion via spacing:
   • Multiple spaces → single space
   • Tabs, newlines → normalized
   • Leading/trailing whitespace → stripped
   
   Preserves intentional line breaks in code blocks

4. Code Block Extraction
   Separates code from narrative text:
   • Fenced code blocks (```language```)
   • Inline code (backtick-wrapped)
   • Returns separate analysis for code vs. text

Usage Example
-------------

from src.core.preprocessor import InputNormalizer

normalizer = InputNormalizer()

# Example 1: Encoded attack payload
encoded = "aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM="  # Base64
normalized, metadata = normalizer.normalize(encoded)
# Output: "ignore all previous instructions"
# metadata.encodings_detected: ["base64"]

# Example 2: Unicode homoglyph attack
homoglyph = "ⅰgnore all previous"  # ⅰ is Roman numeral one, not Latin i
normalized, metadata = normalizer.normalize(homoglyph)
# Output: "ignore all previous"
# metadata.transformations_applied: ["unicode_normalization"]

# Example 3: Code block with embedded threat
code_text = '''Here is some code:
```python
print("ignore all previous")
```
Regular text after.'''

result = normalizer.extract_code_blocks(code_text)
# result['code_blocks']: [{"type": "fenced", "language": "python", "content": "..."}]
# result['text_without_code']: "Here is some code:\n[CODE_BLOCK]\nRegular text after."

Core Components
---------------

InputNormalizer:
  • Main normalization engine
  • Handles all encoding/Unicode/whitespace transformations
  • extract_code_blocks() for code separation

NormalizationMetadata:
  • Tracks all transformations applied
  • encodings_detected: list of encoding types found
  • whitespace_collapsed: count of collapsed whitespace chars
  • transformations_applied: list of transformation names
  • recursion_depth_reached: how deep nested encoding went
  • original_length/normalized_length: before/after sizes

Configuration
--------------

InputNormalizer accepts config dict:

config = {
    "max_recursion_depth": 3,           # Max encoding nesting
    "max_processing_time_ms": 100,      # Timeout per input
    "skip_unicode": False,              # Fast mode (skip Unicode)
}

normalizer = InputNormalizer(config=config)

Test Coverage
-------------

50+ test cases covering:
  ✓ Base64 decoding (single and nested)
  ✓ URL encoding detection
  ✓ Hex encoding detection
  ✓ Unicode homoglyph normalization
  ✓ Zero-width character removal
  ✓ Whitespace collapse (spaces, tabs, newlines)
  ✓ BOM removal
  ✓ Code block extraction (fenced and inline)
  ✓ Mixed encoding layers
  ✓ Edge cases (empty, very long, partially valid)
  ✓ Performance validation (<100ms)

Performance Characteristics
----------------------------

Single input normalization:
  • Typical case: 1-5ms
  • With deep encoding: 5-20ms
  • Timeout protection: 100ms max

Batch normalization:
  • 1000 inputs: ~1-5 seconds
  • Very large corpus: scales linearly

Memory:
  • O(n) where n = input size
  • Recursive stack: O(d) where d = encoding depth

Integration Points
------------------

Upstream (Receives):
  • Raw user input strings
  • API response bodies
  • Encoded payloads from external systems

Downstream (Routes To):
  • Phase 2: PayloadParser (for field extraction)
  • Phase 3: DualGateRouter (for threat detection)
  • Threat detection pipeline

Why This Matters
----------------

Without Phase 1 normalization:
  • Base64-encoded "ignore all previous" bypasses regex patterns
  • Unicode homoglyphs defeat simple string matching
  • Whitespace evasion breaks pattern detection
  • Nested encoding causes analysis failures

With Phase 1:
  • All inputs normalized to canonical form
  • Evasion techniques exposed
  • Consistent, reproducible processing
  • Detection accuracy improved

Example Attack Vectors Defeated
-------------------------------

Attack 1: Base64 encoding
  Input: aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=
  After Phase 1: ignore all previous instructions
  Result: Can now be detected by Tier 1 lexical analysis

Attack 2: Unicode homoglyph substitution
  Input: Á (Cyrillic) instead of A (Latin)
  After Phase 1: Canonical form with Latin characters
  Result: String matching now works

Attack 3: Nested encoding (Base64(Hex(...)))
  Input: Base64-wrapped hex-encoded payload
  After Phase 1: Original payload extracted
  Result: Recursively unwraps multiple encoding layers

Attack 4: Whitespace evasion
  Input: "ignore    all    previous" (extra spaces)
  After Phase 1: "ignore all previous" (single spaces)
  Result: Regex patterns now match
"""
