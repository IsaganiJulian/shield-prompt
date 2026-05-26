"""
Input Normalization Pipeline - Anti-Semantic Drift Layer

Deterministic preprocessing to standardize inputs before Tier 2 ML classification.
Handles Unicode normalization, layered encoding detection, and whitespace collapse.
"""

import base64
import binascii
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import unquote

logger = logging.getLogger(__name__)


@dataclass
class NormalizationMetadata:
    """Metadata about transformations applied during normalization."""
    encodings_detected: List[str] = field(default_factory=list)
    homoglyphs_replaced: int = 0
    whitespace_collapsed: int = 0
    zero_width_chars_removed: int = 0
    original_length: int = 0
    normalized_length: int = 0
    transformations_applied: List[str] = field(default_factory=list)
    recursion_depth_reached: int = 0


class InputNormalizer:
    """
    Lightweight, deterministic preprocessing for ML robustness.

    No ML, no randomness. All operations are reproducible and auditable.
    """

    # Max recursion depth to prevent DoS via nested encoding
    MAX_RECURSION_DEPTH = 3
    MAX_PROCESSING_TIME_MS = 100

    # Common encoding detection thresholds
    BASE64_MIN_LENGTH = 4
    HEX_MIN_LENGTH = 4

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize InputNormalizer.

        Args:
            config: Optional config with max_recursion_depth, skip_unicode, etc.
        """
        self.config = config or {}
        self.max_recursion_depth = self.config.get("max_recursion_depth", self.MAX_RECURSION_DEPTH)
        self.skip_unicode = self.config.get("skip_unicode", False)
        logger.info(f"InputNormalizer initialized (max_depth={self.max_recursion_depth})")

    def normalize(
        self,
        raw_input: str,
        lightweight_mode: bool = False
    ) -> Tuple[str, NormalizationMetadata]:
        """
        Main normalization pipeline.

        Args:
            raw_input: Raw, untrusted input string
            lightweight_mode: If True, skip Unicode normalization for speed (for shield_context)

        Returns:
            (normalized_text, NormalizationMetadata)
        """
        metadata = NormalizationMetadata(original_length=len(raw_input))

        if not raw_input:
            metadata.normalized_length = 0
            return "", metadata

        # Pipeline order matters:
        # 1. Decode encodings (outermost layer first)
        # 2. Unicode normalization (collapse homoglyphs)
        # 3. Whitespace collapse (clean formatting)
        # 4. Zero-width character removal (inline obfuscation)

        text = raw_input

        # Step 1: Decode layered encodings
        text, encoding_meta = self._decode_layered_encoding(text)
        metadata.encodings_detected = encoding_meta["encodings_found"]
        metadata.recursion_depth_reached = encoding_meta["recursion_depth"]
        if encoding_meta["encodings_found"]:
            metadata.transformations_applied.append("layered_decoding")

        # Step 2: Unicode normalization (skip if lightweight_mode or configured)
        if not lightweight_mode and not self.skip_unicode:
            unicode_before = len(text)
            text, homoglyphs_count = self._normalize_unicode(text)
            metadata.homoglyphs_replaced = homoglyphs_count
            if homoglyphs_count > 0:
                metadata.transformations_applied.append("unicode_normalization")

        # Step 3: Whitespace collapse
        whitespace_before = len(text)
        text = self._collapse_whitespace(text)
        metadata.whitespace_collapsed = whitespace_before - len(text)
        if metadata.whitespace_collapsed > 0:
            metadata.transformations_applied.append("whitespace_collapse")

        # Step 4: Zero-width character removal
        zero_width_before = len(text)
        text = self._remove_zero_width_chars(text)
        metadata.zero_width_chars_removed = zero_width_before - len(text)
        if metadata.zero_width_chars_removed > 0:
            metadata.transformations_applied.append("zero_width_removal")

        metadata.normalized_length = len(text)

        logger.debug(
            f"Normalization complete: {metadata.original_length} → {metadata.normalized_length} chars, "
            f"transforms={metadata.transformations_applied}"
        )

        return text, metadata

    def _decode_layered_encoding(self, text: str, depth: int = 0) -> Tuple[str, Dict[str, Any]]:
        """
        Recursively decode Base64 → Hex → URL layers.

        Example:
            Input: Base64(Hex(URL("ignore%20all%20previous")))
            Output: ("ignore all previous", {encodings_found: ["base64", "hex", "url"]})

        Safety: Max recursion depth prevents zip-bomb style attacks.

        Args:
            text: Text to decode
            depth: Current recursion depth (tracks how many layers decoded)

        Returns:
            (decoded_text, metadata)
        """
        metadata = {"encodings_found": [], "recursion_depth": depth}

        if depth >= self.max_recursion_depth:
            logger.debug(f"Max recursion depth ({self.max_recursion_depth}) reached")
            return text, metadata

        # Try each encoding type (order matters - try Base64 first as it's most common)
        # Base64
        if self._looks_like_base64(text):
            try:
                decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
                if decoded != text:  # Only recurse if we actually decoded something
                    metadata["encodings_found"].append("base64")
                    # Recurse to check for nested encoding
                    decoded, nested_meta = self._decode_layered_encoding(decoded, depth + 1)
                    metadata["encodings_found"].extend(nested_meta["encodings_found"])
                    metadata["recursion_depth"] = nested_meta["recursion_depth"]
                    return decoded, metadata
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass

        # Hex
        if self._looks_like_hex(text):
            try:
                decoded = bytes.fromhex(text).decode("utf-8", errors="replace")
                if decoded != text:
                    metadata["encodings_found"].append("hex")
                    decoded, nested_meta = self._decode_layered_encoding(decoded, depth + 1)
                    metadata["encodings_found"].extend(nested_meta["encodings_found"])
                    metadata["recursion_depth"] = nested_meta["recursion_depth"]
                    return decoded, metadata
            except (ValueError, UnicodeDecodeError):
                pass

        # URL encoding
        try:
            decoded = unquote(text)
            if decoded != text and "%" in text:  # Only count as URL encoded if it had % signs
                metadata["encodings_found"].append("url")
                decoded, nested_meta = self._decode_layered_encoding(decoded, depth + 1)
                metadata["encodings_found"].extend(nested_meta["encodings_found"])
                metadata["recursion_depth"] = nested_meta["recursion_depth"]
                return decoded, metadata
        except Exception:
            pass

        # No encoding detected, return original
        return text, metadata

    def _looks_like_base64(self, text: str) -> bool:
        """
        Heuristic check if text looks like Base64.

        Base64 alphabet: A-Z, a-z, 0-9, +, /, = (padding)
        Real Base64 typically: length multiple of 4, high ratio of alphanumeric.
        """
        if len(text) < self.BASE64_MIN_LENGTH:
            return False

        # Check if mostly Base64 characters
        base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
        if not base64_pattern.match(text):
            return False

        # Length should be multiple of 4
        if len(text) % 4 != 0:
            return False

        return True

    def _looks_like_hex(self, text: str) -> bool:
        """
        Heuristic check if text looks like hexadecimal.

        Hex alphabet: 0-9, a-f, A-F
        Even length typically required.
        """
        if len(text) < self.HEX_MIN_LENGTH:
            return False

        # Check if all hex characters
        if not all(c in "0123456789abcdefABCDEF" for c in text):
            return False

        # Hex should be even length
        if len(text) % 2 != 0:
            return False

        return True

    def _normalize_unicode(self, text: str) -> Tuple[str, int]:
        """
        NFKD normalization to collapse homoglyphs and Unicode variations.

        Examples:
            - "ⅰgnore" (Roman numeral i U+2170) → "ignore"
            - "igno​re" (zero-width space U+200B) → "ignore"
            - "ӏgnore" (Cyrillic small L U+04CF) → "ignore"
            - "℃" (Degree Celsius U+2103) → "°C"

        Also removes control characters (except newlines, tabs for structure preservation).

        Args:
            text: Text to normalize

        Returns:
            (normalized_text, count_of_homoglyphs_replaced)
        """
        before = text

        # NFKD normalization: compatibility decomposition
        normalized = unicodedata.normalize("NFKD", text)

        # Remove control characters (category Cc) except tab (U+0009) and newline (U+000A)
        # Also remove format characters (category Cf) like zero-width spaces
        cleaned = "".join(
            c for c in normalized
            if unicodedata.category(c) not in ("Cc", "Cf") or c in ("\t", "\n")
        )

        # Count how many characters changed (homoglyph replacements + control removal)
        homoglyphs_replaced = len(before) - len(cleaned)

        return cleaned, homoglyphs_replaced

    def _collapse_whitespace(self, text: str) -> str:
        """
        Collapse consecutive whitespace.

        - Replace 2+ consecutive spaces/tabs with single space
        - Strip leading/trailing whitespace
        - Preserve single newlines but collapse multiple newlines to single

        Args:
            text: Text to process

        Returns:
            Cleaned text
        """
        # Collapse multiple spaces/tabs to single space (but preserve newlines)
        text = re.sub(r"[ \t]{2,}", " ", text)

        # Collapse multiple newlines to single newline
        text = re.sub(r"\n{2,}", "\n", text)

        # Strip leading/trailing whitespace
        text = text.strip()

        return text

    def _remove_zero_width_chars(self, text: str) -> str:
        """
        Remove zero-width characters used for obfuscation.

        Zero-width chars: U+200B, U+200C, U+200D, U+FEFF (BOM), etc.

        Args:
            text: Text to process

        Returns:
            Text with zero-width chars removed
        """
        # Zero-width joiner, zero-width non-joiner, zero-width space, BOM
        zero_width_chars = ["\u200B", "\u200C", "\u200D", "\uFEFF"]

        for zwc in zero_width_chars:
            text = text.replace(zwc, "")

        return text

    def extract_code_blocks(self, text: str) -> Dict[str, Any]:
        """
        Identify and separately track markdown code blocks.

        Code in backticks should be flagged differently than prose.

        Args:
            text: Raw text with potential code blocks

        Returns:
            {
                "text_without_code": "...",
                "code_blocks": [
                    {"content": "...", "language": "python", "line_start": 5}
                ],
                "code_block_count": int
            }
        """
        code_blocks = []
        text_without_code = text

        # Fenced code blocks (```language ... ```)
        # More flexible pattern: allows optional newlines after opening/before closing
        fenced_pattern = r"```(\w*)\s*(.*?)\s*```"
        for match in re.finditer(fenced_pattern, text, re.DOTALL):
            language = match.group(1) or "text"
            content = match.group(2).strip()
            start_pos = match.start()
            line_start = text[:start_pos].count("\n") + 1

            code_blocks.append({
                "content": content,
                "language": language,
                "line_start": line_start,
                "type": "fenced"
            })

        # Inline code blocks (`...`)
        inline_pattern = r"`([^`]+)`"
        for match in re.finditer(inline_pattern, text):
            if match.start() < len(text):  # Exclude fenced block content
                content = match.group(1)
                code_blocks.append({
                    "content": content,
                    "language": "inline",
                    "type": "inline"
                })

        # Remove code blocks from text (replace with placeholder)
        text_without_code = re.sub(fenced_pattern, "[CODE_BLOCK]", text, flags=re.DOTALL)
        text_without_code = re.sub(inline_pattern, "[INLINE_CODE]", text_without_code)

        return {
            "text_without_code": text_without_code,
            "code_blocks": code_blocks,
            "code_block_count": len(code_blocks)
        }
