"""Embedding backends.

Default is a **deterministic hashing TF-IDF embedder** (stdlib only):

* zero network calls, so it works air-gapped;
* identical output across machines, Python versions and runs — essential when an
  examiner re-runs a retrieval months later and must get the same citation;
* no model download, so ``pip install`` is the whole install story.

Optional API embeddings (OpenAI / Mistral / Ollama) can be enabled with
``anjali config set rag.embedder api``. Vectors are namespaced by model so switching
backends never corrupts the index.
"""

from __future__ import annotations

import hashlib
import json
import math
from array import array
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any

import httpx

from anjali.core.errors import ProviderError
from anjali.core.util import normalise_name, tokenize

DEFAULT_DIM = 768
DEFAULT_EMBEDDER_TAG = "hashtfidf-v1"


class LocalTfidfEmbedder:
    """Signed hashing of word uni/bi-grams + char 4-grams, IDF-weighted."""

    tag = DEFAULT_EMBEDDER_TAG

    def __init__(self, dim: int = DEFAULT_DIM, idf: dict[str, float] | None = None) -> None:
        self.dim = dim
        self.idf = idf or {}
        self._default_idf = 1.0

    # -- fitting ---------------------------------------------------------- #
    def fit(self, texts: Sequence[str]) -> LocalTfidfEmbedder:
        df: Counter[str] = Counter()
        n = max(1, len(texts))
        for text in texts:
            for feat in set(self.features(text)):
                df[feat] += 1
        # Smoothed IDF; unseen features at query time fall back to the max seen.
        self.idf = {f: math.log((1 + n) / (1 + c)) + 1.0 for f, c in df.items()}
        self._default_idf = max(self.idf.values()) if self.idf else 1.0
        return self

    def state(self) -> dict[str, Any]:
        return {"tag": self.tag, "dim": self.dim, "idf": self.idf}

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> LocalTfidfEmbedder:
        return cls(dim=int(state.get("dim", DEFAULT_DIM)), idf=state.get("idf") or {})

    # -- features --------------------------------------------------------- #
    @staticmethod
    def features(text: str) -> list[str]:
        """Feature strings. Prefixes keep the three families separable."""
        toks = tokenize(text)
        content = [t for t in toks if len(t) > 1]
        feats: list[str] = [f"w:{t}" for t in content]
        feats.extend(f"b:{a}_{b}" for a, b in zip(content, content[1:]))
        # Char 4-grams over long tokens catch morphological variants:
        # "structuring"/"structured", "smurfing"/"smurfs", "launder"/"laundering".
        for tok in content:
            if len(tok) >= 6 and any(ch.isalpha() for ch in tok):
                padded = f"_{tok}_"
                feats.extend(f"c:{padded[i : i + 4]}" for i in range(len(padded) - 3))
        # Citation-shaped tokens get extra weight through repetition.
        for tok in content:
            if any(ch.isdigit() for ch in tok) and "." in tok:
                feats.append(f"x:{tok}")
                feats.append(f"x:{tok}")
        return feats

    def _bucket(self, feat: str) -> tuple[int, float]:
        digest = hashlib.blake2b(feat.encode(), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "little") % self.dim
        sign = 1.0 if digest[4] & 1 else -1.0
        return idx, sign

    # -- embedding -------------------------------------------------------- #
    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        counts = Counter(self.features(text))
        if not counts:
            return vec
        for feat, tf in counts.items():
            weight = (1.0 + math.log(tf)) * self.idf.get(feat, self._default_idf)
            idx, sign = self._bucket(feat)
            vec[idx] += sign * weight
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0:
            return vec
        return [v / norm for v in vec]

    def embed_many(self, texts: Iterable[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


class ApiEmbedder:
    """OpenAI-compatible embeddings endpoint. Never used unless explicitly enabled."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str | None,
        *,
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.tag = f"api-{model}"

    def embed(self, text: str) -> list[float]:
        return self.embed_many([text])[0]

    def embed_many(self, texts: Iterable[str]) -> list[list[float]]:
        batch = list(texts)
        if not batch:
            return []
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    f"{self.base_url}/embeddings",
                    json={"model": self.model, "input": batch},
                    headers=headers,
                )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Embedding request failed: {exc}",
                hint="Fall back with: anjali config set rag.embedder local",
            ) from exc
        rows = sorted(data.get("data", []), key=lambda d: d.get("index", 0))
        return [row["embedding"] for row in rows]


# --------------------------------------------------------------------------- #
# Vector (de)serialisation
# --------------------------------------------------------------------------- #
def pack_vector(vec: Sequence[float]) -> bytes:
    return array("f", vec).tobytes()


def unpack_vector(blob: bytes) -> list[float]:
    arr = array("f")
    arr.frombytes(blob)
    return arr.tolist()


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Assumes L2-normalised inputs in most paths; falls back to full formula."""
    if not a or not b:
        return 0.0
    if len(a) != len(b):
        return 0.0
    dot = na = nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0 or nb == 0:
        return 0.0
    return dot / math.sqrt(na * nb)


def build_embedder(settings: Any) -> LocalTfidfEmbedder | ApiEmbedder:
    """Resolve the configured embedder; API mode degrades gracefully to local."""
    if settings.rag.embedder == "api":
        provider = settings.provider
        from anjali.core.config import EMBEDDING_MODELS

        model = EMBEDDING_MODELS.get(provider.name)
        if model and provider.base_url:
            return ApiEmbedder(model, provider.base_url, provider.api_key)
    return LocalTfidfEmbedder()


def dumps_idf(embedder: LocalTfidfEmbedder) -> str:
    return json.dumps(embedder.state(), separators=(",", ":"))


def loads_idf(payload: str) -> LocalTfidfEmbedder:
    return LocalTfidfEmbedder.from_state(json.loads(payload))


def name_fingerprint(name: str) -> str:
    """Used by grape/graph matching and by screening explainability."""
    return normalise_name(name)
