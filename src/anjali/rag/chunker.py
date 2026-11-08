"""Section-aware chunking for legal text.

Legal citations are structural: an answer that cites "31 CFR § 1010.314" must map to a
chunk whose boundaries respect that provision, not to an arbitrary 512-token window.
Chunks therefore split on statutory markers first and only then on length.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from anjali.core.util import strip_accents

DEFAULT_MAX_CHARS = 1100
DEFAULT_OVERLAP = 140

# Markers that begin a new legal sub-provision.
_MARKER = re.compile(
    r"(?m)^[ \t]*(?:"
    r"\((?:\d{1,2}|[a-z]|[ivx]{1,5})\)"      # (a) (1) (iv)
    r"|Article\s+\d+"                        # Article 3
    r"|Section\s+\d+"                        # Section 4
    r"|Sec\.\s*\d+"
    r"|§\s*[\d.]+"
    r"|(?:19|20)\d{2}\s+Amendment"           # "2025 Amendment"
    r")\b"
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.;:])\s+(?=[A-Z(])")


@dataclass
class TextChunk:
    section: str | None
    text: str
    ordinal: int


def _split_paragraphs(text: str) -> list[str]:
    text = text.replace("\r\n", "\n").strip()
    blocks: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        if not para:
            continue
        # Break a paragraph at sub-provision markers that start a line.
        positions = [m.start() for m in _MARKER.finditer(para)]
        if not positions or (positions[0] > 0 and len(para) < 400):
            blocks.append(para)
            continue
        if positions[0] != 0:
            blocks.append(para[: positions[0]].strip())
        for i, start in enumerate(positions):
            end = positions[i + 1] if i + 1 < len(positions) else len(para)
            piece = para[start:end].strip()
            if piece:
                blocks.append(piece)
    return blocks


def _window(block: str, max_chars: int, overlap: int) -> list[str]:
    """Split an over-long block on sentence boundaries with trailing overlap."""
    if len(block) <= max_chars:
        return [block]
    sentences = _SENTENCE_SPLIT.split(block)
    out: list[str] = []
    buf = ""
    for sent in sentences:
        if not buf:
            buf = sent
        elif len(buf) + len(sent) + 1 <= max_chars:
            buf = f"{buf} {sent}"
        else:
            out.append(buf)
            tail = buf[-overlap:] if overlap and len(buf) > overlap else ""
            buf = f"{tail} {sent}".strip() if tail else sent
    if buf:
        out.append(buf)
    # Hard-split anything still oversized (e.g. one giant sentence).
    final: list[str] = []
    for piece in out:
        while len(piece) > max_chars * 1.6:
            final.append(piece[:max_chars])
            piece = piece[max_chars - overlap :]
        if piece:
            final.append(piece)
    return final


def _section_label(text: str, fallback: str | None) -> str | None:
    m = _MARKER.match(text.strip())
    if m:
        return m.group(0).strip()
    head = text.strip().split("\n", 1)[0]
    if len(head) < 90 and head.endswith(":"):
        return head.rstrip(":")
    return fallback


def chunk_text(
    text: str,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap: int = DEFAULT_OVERLAP,
    heading: str | None = None,
) -> list[TextChunk]:
    blocks = _split_paragraphs(strip_accents(text))
    chunks: list[TextChunk] = []
    buf_blocks: list[str] = []
    section: str | None = heading

    def flush() -> None:
        nonlocal buf_blocks
        if not buf_blocks:
            return
        joined = "\n".join(buf_blocks).strip()
        for piece in _window(joined, max_chars, overlap):
            chunks.append(
                TextChunk(section=_section_label(piece, section), text=piece, ordinal=len(chunks))
            )
        buf_blocks = []

    for block in blocks:
        if _MARKER.match(block) and buf_blocks:
            flush()
            section = _section_label(block, section)
        candidate_len = len("\n".join([*buf_blocks, block]))
        if candidate_len > max_chars and buf_blocks:
            flush()
        buf_blocks.append(block)
    flush()
    return chunks or [TextChunk(section=heading, text=text.strip(), ordinal=0)]


def snippet_for(text: str, terms: list[str], width: int = 320) -> str:
    """Return a citation-friendly window centred on the first matched term."""
    flat = " ".join(text.split())
    if not terms:
        return flat[:width] + ("…" if len(flat) > width else "")
    lower = flat.lower()
    hit = -1
    for term in terms:
        if not term:
            continue
        hit = lower.find(term.lower())
        if hit >= 0:
            break
    if hit < 0:
        return flat[:width] + ("…" if len(flat) > width else "")
    start = max(0, hit - width // 3)
    end = min(len(flat), start + width)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(flat) else ""
    return f"{prefix}{flat[start:end]}{suffix}"
