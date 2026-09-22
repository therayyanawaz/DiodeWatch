"""Laya System-1 decision runtime (ONNX) — Python port of the reference
implementation (checkpoint `rl_common.py` / `rl_agent_api.py`, TS port
`receptron/laya`).

Laya is a ModernBERT encoder + decision head exported to one ONNX graph
(`export_onnx.py` in receptron/laya). It does not generate text: you hand it
a state (any JSON-able object) and typed questions, and one forward pass
answers every question with calibrated probabilities:

  * choice — pick one option, with a probability per option;
  * score  — an expected level on an ordered rubric, with the distribution;
  * noul   — a calibrated P(true) for a yes/no statement.

Everything here runs offline inside the analytics enclave: the bundle is read
from disk (models/laya-onnx/), the session is CPU ONNX Runtime, and no
network call is ever made at inference time (huggingface_hub is a fetch-time
dependency only, see scripts/fetch/fetch_laya.py).

Sequence contract (must stay byte-faithful to the reference, or the
calibrated temperatures stop meaning anything):

    [CLS] <type> question: instructions [SEP] [MASK] opt0 [MASK] opt1 ...
    [SEP] state [SEP]

with the head capped at head_max_len tokens (options shrink evenly when they
overflow), the state capped into the remaining room, and right-padding to the
batch max. Answers come from temperature-scaled softmax over each question's
option logits (per-type/per-cardinality calibration from laya_config.json)
plus the act head's P(answer-honest) — exposed as `act_probability`.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

try:
    import onnxruntime as ort
except ImportError as _e:  # pragma: no cover - environment-specific
    ort = None
    _ORT_IMPORT_ERROR = _e
else:
    _ORT_IMPORT_ERROR = None

BUNDLE_FILES = (
    "laya.onnx",
    "laya.onnx.data",  # external weights data referenced by the graph
    "laya_config.json",
    "tokenizer/tokenizer.json",
    "tokenizer/tokenizer_config.json",
)

QTYPES = {"choice": 0, "score": 1, "noul": 2}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}

DEFAULT_BUNDLE_DIR = Path("models/laya-onnx")

# The pinned Hugging Face revision of the bundle (single source of truth;
# scripts/fetch/fetch_laya.py re-exports this). Stored in every verdict envelope
# so each decision carries its model provenance.
MODEL_REVISION = "68f27dfe5a27a54fb2b1fefc432f43f972e90868"
MODEL_NAME = "laya-onnx (receptron/laya export)"


def bundle_sha256(model_dir: str | Path = DEFAULT_BUNDLE_DIR) -> str | None:
    """SHA256 of laya.onnx.data — the weights file (not the whole bundle).

    The graph file laya.onnx is fixed by MODEL_REVISION; this digest pins the
    weights bytes. None when the file is absent. Hashing the 1.6 GB weights
    takes a moment, so callers hash once per process and reuse the digest.
    """
    import hashlib
    p = Path(model_dir) / "laya.onnx.data"
    if not p.exists():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class LayaUnavailable(RuntimeError):
    """Laya runtime or bundle is missing — callers must degrade, not crash."""


# --------------------------------------------------------------------------- #
# questions
# --------------------------------------------------------------------------- #
@dataclass
class Question:
    """One typed question about a state (Jev system_one shape)."""
    type: str                                   # "choice" | "score" | "noul"
    instructions: str
    # choice: option -> description-or-None; score: ordered levels;
    # noul: optional {"true": ..., "false": ...} criteria.
    criteria: Any = None


@dataclass
class Answer:
    """One answer, shaped by its question type."""
    type: str
    # choice
    choice: str | None = None
    # score (expected level 0..levels-1)
    score: float | None = None
    legend: dict[str, str] | None = None
    # noul P(true)
    noul: float | None = None
    # shared
    probabilities: dict[str, float] | None = None
    confidence: float = 0.0          # 1 - normalized entropy of p
    act_probability: float = 0.0     # act head P(answer honest)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type,
                             "confidence": round(self.confidence, 4),
                             "act_probability": round(self.act_probability, 4)}
        if self.type == "choice":
            d["choice"] = self.choice
        elif self.type == "score":
            d["score"] = self.score
            d["legend"] = self.legend
        elif self.type == "noul":
            d["noul"] = self.noul
        if self.probabilities is not None:
            d["probabilities"] = {k: round(v, 4)
                                  for k, v in self.probabilities.items()}
        return d


@dataclass
class SystemOneResult:
    answers: dict[str, Answer]
    input_tokens: int
    model_dir: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": "laya",
            "input_tokens": self.input_tokens,
            "model_dir": self.model_dir,
            "answers": {k: v.to_dict() for k, v in self.answers.items()},
        }


# --------------------------------------------------------------------------- #
# pure rendering helpers (unit-tested without the bundle)
# --------------------------------------------------------------------------- #
def py_json_dumps(v: Any) -> str:
    """Python's json.dumps(obj, ensure_ascii=False): ", " / ": " separators,
    insertion key order — the state serialization the model was trained on."""
    if v is None:
        return "null"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(py_json_dumps(x) for x in v) + "]"
    if isinstance(v, dict):
        return ("{" + ", ".join(f"{json.dumps(str(k), ensure_ascii=False)}: "
                                f"{py_json_dumps(x)}"
                                for k, x in v.items()) + "}")
    return py_json_dumps(str(v))


def serialize_state(state: Any) -> str:
    return state if isinstance(state, str) else py_json_dumps(state)


def render_options(q: Question) -> list[str]:
    """Option texts in label-index order. Noul is always [false, true] so
    p[1] == P(true)."""
    if q.type == "choice":
        crit = q.criteria or {}
        if isinstance(crit, (list, tuple)):
            crit = {c: None for c in crit}
        return [k if not v else f"{k}: {v}" for k, v in crit.items()]
    if q.type == "score":
        return [f"level {i}: {c}" for i, c in enumerate(q.criteria or [])]
    crit = q.criteria or {}
    if not isinstance(crit, dict):
        crit = {}
    return ["false: " + (crit.get("false") or "no, the statement does not hold"),
            "true: " + (crit.get("true") or "yes, the statement holds")]


def size_bucket(k: int) -> str:
    if k <= 2:
        return "2"
    if k <= 5:
        return "3-5"
    if k <= 10:
        return "6-10"
    return "11+"


def temp_bucket(qtype: int, k: int) -> str:
    """Per-cardinality calibration key: a 2-option noul and a 20-option
    choice are fitted with different temperatures."""
    return f"{QTYPE_NAMES[int(qtype)]}:{size_bucket(k)}"


def softmax(z: list[float]) -> list[float]:
    if not z:
        return []
    zmax = max(z)
    e = [math.exp(v - zmax) for v in z]
    s = sum(e)
    return [v / s for v in e] if s > 0 else [1.0 / len(z)] * len(z)


def confidence_from_probs(p: list[float]) -> float:
    """Jev-style confidence: 1 - normalized entropy of the distribution."""
    k = len(p)
    if k < 2:
        return 1.0
    ent = -sum(x * math.log(max(x, 1e-12)) for x in p)
    return 1.0 - ent / math.log(k)


def _internal(q: Question) -> Question:
    """Normalize: a choice question given a list becomes option->None."""
    if q.type == "choice" and isinstance(q.criteria, (list, tuple)):
        return Question(q.type, q.instructions,
                        {c: None for c in q.criteria})
    return q


def build_sequence(encode, ids_map: dict[str, int], state: Any, q: Question,
                   max_len: int, head_max_len: int) -> tuple[list[int], list[int]]:
    """The reference layout. `encode(text) -> ids` adds no special tokens.

    Returns (input_ids, marker_positions) — one [MASK] marker per option.
    """
    mask_tok = "[MASK]"
    scrub = lambda s: s.replace(mask_tok, " ")
    opts = render_options(q)
    ins = str(q.instructions).replace(mask_tok, " ")
    head_ids = encode(f"{q.type} question: {scrub(ins)}")
    opt_ids = [[ids_map["mask"]] + encode(" " + scrub(o))[:48] for o in opts]
    opt_budget = head_max_len - sum(len(o) for o in opt_ids)
    if opt_budget < 16:
        # too many / too long options: shrink every option text evenly
        per = max(4, (head_max_len - 16) // max(1, len(opt_ids)))
        opt_ids = [o[:per] for o in opt_ids]
        opt_budget = head_max_len - sum(len(o) for o in opt_ids)
    head_ids = head_ids[:max(8, opt_budget)]

    seq = [ids_map["cls"]] + head_ids + [ids_map["sep"]]
    markers: list[int] = []
    for o in opt_ids:
        markers.append(len(seq))
        seq.extend(o)
    seq.append(ids_map["sep"])
    room = max(0, max_len - len(seq) - 1)
    st = encode(scrub(serialize_state(state)))[:room]
    seq.extend(st)
    seq.append(ids_map["sep"])
    return seq[:max_len], [m for m in markers if m < max_len]


# --------------------------------------------------------------------------- #
# tokenizer (HF fast tokenizer json, add_special_tokens=False everywhere)
# --------------------------------------------------------------------------- #
class BundleTokenizer:
    """Thin wrapper over tokenizers.Tokenizer with the special-token ids the
    sequence builder needs."""

    def __init__(self, tok_json: dict, tok_cfg: dict) -> None:
        try:
            from tokenizers import Tokenizer
        except ImportError as e:  # pragma: no cover - environment-specific
            raise LayaUnavailable(
                "the 'tokenizers' package is required for the Laya runtime "
                "(pip install tokenizers)") from e
        self._tok = Tokenizer.from_str(json.dumps(tok_json))
        self.cfg = tok_cfg

    def _id(self, token: str) -> int:
        v = self._tok.token_to_id(token)
        if v is None:
            raise LayaUnavailable(f"special token {token!r} missing from the "
                                  "Laya tokenizer")
        return int(v)

    @property
    def ids(self) -> dict[str, int]:
        return {"cls": self._id("[CLS]"), "sep": self._id("[SEP]"),
                "mask": self._id("[MASK]"), "pad": self._id("[PAD]")}

    def encode(self, text: str) -> list[int]:
        return self._tok.encode(text, add_special_tokens=False).ids


# --------------------------------------------------------------------------- #
# session
# --------------------------------------------------------------------------- #
@dataclass
class _Item:
    q: Question
    ids: list[int]
    markers: list[int]
    qtype: int


class Laya:
    """Loaded Laya ONNX session; answer questions about a state offline."""

    def __init__(self, session, tok: BundleTokenizer, config: dict,
                 model_dir: str | Path) -> None:
        if ort is None:  # pragma: no cover - environment-specific
            raise LayaUnavailable(
                "onnxruntime is not installed — the Laya channel degrades to "
                "silent (pip install onnxruntime)") from _ORT_IMPORT_ERROR
        self.session = session
        self.tok = tok
        self.config = config
        self.model_dir = str(model_dir)
        self.model_revision = MODEL_REVISION
        self.model_name = MODEL_NAME
        self.bundle_sha256: str | None = None  # hashed lazily, once, on first verdict
        self.ids = tok.ids
        self.max_len = int(config.get("max_len", 512))
        self.head_max_len = int(config.get("head_max_len", 192))
        self.temperature = config.get("temperature", [1.0, 1.0, 1.0])
        self.temperature_by_options: dict[str, float] = config.get(
            "temperature_by_options", {})

    @classmethod
    def load(cls, model_dir: str | Path = DEFAULT_BUNDLE_DIR,
             execution_providers: list[str] | None = None,
             intra_op_threads: int | None = None) -> Laya:
        """Load the bundle from disk. Raises LayaUnavailable with an honest
        reason when anything is missing (callers degrade to silent)."""
        d = Path(model_dir)
        missing = [f for f in BUNDLE_FILES if not (d / f).exists()]
        if missing:
            raise LayaUnavailable(
                f"Laya bundle incomplete at {d} (missing: {', '.join(missing)}) "
                "— run `python scripts/fetch/fetch_laya.py` to download it once "
                "(offline afterwards)")
        if ort is None:  # pragma: no cover - environment-specific
            raise LayaUnavailable(
                "onnxruntime is not installed — run "
                "`pip install onnxruntime` to enable the Laya triage channel"
            ) from _ORT_IMPORT_ERROR
        try:
            config = json.loads((d / "laya_config.json").read_text("utf-8"))
            tok = BundleTokenizer(
                json.loads((d / "tokenizer" / "tokenizer.json")
                           .read_text("utf-8")),
                json.loads((d / "tokenizer" / "tokenizer_config.json")
                           .read_text("utf-8")))
            so = ort.SessionOptions()
            so.graph_optimization_level = \
                ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            if intra_op_threads:
                so.intra_op_num_threads = int(intra_op_threads)
            eps = (list(execution_providers)
                   if execution_providers
                   # DmlExecutionProvider crashes on this dynamo-exported
                   # graph (Reshape 'node_view'); CPU is the tested default.
                   else [p for p in ort.get_available_providers()
                        if p != "DmlExecutionProvider"]
                   or ["CPUExecutionProvider"])
            session = ort.InferenceSession(
                str(d / "laya.onnx"), so,
                providers=eps)
        except (OSError, json.JSONDecodeError) as e:
            raise LayaUnavailable(f"Laya bundle unreadable at {d}: {e}") from e
        return cls(session, tok, config, d)

    @staticmethod
    def available(model_dir: str | Path = DEFAULT_BUNDLE_DIR) -> bool:
        d = Path(model_dir)
        return ort is not None and all((d / f).exists() for f in BUNDLE_FILES)

    # ------------------------------------------------------------------ core
    def system_one(self, state: Any,
                   questions: dict[str, Question]) -> SystemOneResult:
        """Answer every question about one state in a single forward pass."""
        if not questions:
            raise ValueError("system_one: at least one question is required")
        qids = list(questions.keys())
        items: list[_Item] = []
        for qid in qids:
            q = _internal(questions[qid])
            ids, markers = build_sequence(self.tok.encode, self.ids, state, q,
                                          self.max_len, self.head_max_len)
            if len(markers) != len(render_options(q)):
                raise ValueError(
                    f"question {qid!r}: options do not fit in "
                    f"head_max_len={self.head_max_len} tokens")
            items.append(_Item(q, ids, markers, QTYPES[q.type]))

        # collate: right-pad to the longest sequence / widest option set
        n = len(items)
        L = max(len(it.ids) for it in items)
        K = max(len(it.markers) for it in items)
        pad = self.ids["pad"]
        input_ids = np.full((n, L), pad, dtype=np.int64)
        attention = np.zeros((n, L), dtype=np.int64)
        marker_pos = np.zeros((n, K), dtype=np.int64)
        marker_mask = np.zeros((n, K), dtype=bool)
        qtype = np.zeros((n,), dtype=np.int64)
        for i, it in enumerate(items):
            input_ids[i, :len(it.ids)] = it.ids
            attention[i, :len(it.ids)] = 1
            marker_pos[i, :len(it.markers)] = it.markers
            marker_mask[i, :len(it.markers)] = True
            qtype[i] = it.qtype

        out = self.session.run(
            ["logits", "act_probs"],
            {"input_ids": input_ids, "attention_mask": attention,
             "marker_pos": marker_pos, "marker_mask": marker_mask,
             "qtype": qtype})
        logits = np.asarray(out[0], dtype=np.float32)
        act_probs = np.asarray(out[1], dtype=np.float32)

        answers: dict[str, Answer] = {}
        n_tokens = 0
        for r, it in enumerate(items):
            k = len(it.markers)
            n_tokens += len(it.ids)
            bucket = temp_bucket(it.qtype, k)
            temp = self.temperature_by_options.get(
                bucket, self.temperature[it.qtype] if it.qtype <
                len(self.temperature) else 1.0)
            p = softmax([float(v) for v in logits[r, :k] / temp])
            act = float(act_probs[r, 0]) if act_probs.ndim == 2 else 0.0
            q = it.q
            if q.type == "choice":
                keys = list((q.criteria or {}).keys()) \
                    if not isinstance(q.criteria, (list, tuple)) \
                    else list(q.criteria)
                best = int(np.argmax(p))
                answers[qids[r]] = Answer(
                    type="choice", choice=keys[best],
                    probabilities={kk: p[i] for i, kk in enumerate(keys)},
                    confidence=confidence_from_probs(p), act_probability=act)
            elif q.type == "score":
                crit = list(q.criteria or [])
                answers[qids[r]] = Answer(
                    type="score",
                    score=round(sum(i * v for i, v in enumerate(p)), 4),
                    legend={str(i): c for i, c in enumerate(crit)},
                    probabilities={str(i): v for i, v in enumerate(p)},
                    confidence=confidence_from_probs(p), act_probability=act)
            else:
                answers[qids[r]] = Answer(
                    type="noul", noul=p[1] if len(p) > 1 else 0.0,
                    confidence=confidence_from_probs(p), act_probability=act)
        return SystemOneResult(answers=answers, input_tokens=n_tokens,
                               model_dir=self.model_dir)

    def close(self) -> None:
        # Drop the session reference so the runtime can reclaim the weights.
        self.session = None
