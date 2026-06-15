"""A minimal memory-augmented reasoning agent.

This distils the common structure shared by the three agents attacked in the
paper (RAP, EHRAgent, QA Agent):

    retrieve top-k similar past records  ->  build an in-context prompt
    ->  LLM produces reasoning + answer  ->  *optionally* write the record back
        into the shared memory bank.

The two knobs that the paper's whole threat model hinges on are made explicit
here so they can be toggled in ablations:

* ``retrieval`` -- how past records are scored. The runnable QA agent in the
  original repo uses **Levenshtein edit distance** on the raw question string
  (NOT the ada-002 embedding the paper's text claims), so that is the default.
  An embedding-ish cosine on bag-of-words is also provided.

* ``write_back_gate`` -- the predicate that decides whether a finished record
  enters memory. EHR/QA store *everything*; RAP claims to store only
  user-approved records but the attack code forges that approval. This gate is
  the real lock on the front door, so we make it a first-class, swappable
  policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Dict, Optional

from llm import Demo


# --------------------------------------------------------------------------- #
# Retrieval functions: (query, memory_item) -> distance  (smaller = closer)
# --------------------------------------------------------------------------- #
def levenshtein(a: str, b: str) -> int:
    """Plain edit distance (the QA agent's actual retrieval metric)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def edit_distance_retrieval(query: str, item: Dict) -> float:
    return float(levenshtein(query, item["question"]))


def _bow(s: str):
    from collections import Counter
    return Counter(s.lower().split())


def cosine_bow_retrieval(query: str, item: Dict) -> float:
    """1 - cosine similarity of bag-of-words vectors (an embedding stand-in)."""
    import math
    qa, qb = _bow(query), _bow(item["question"])
    keys = set(qa) | set(qb)
    dot = sum(qa[k] * qb[k] for k in keys)
    na = math.sqrt(sum(v * v for v in qa.values()))
    nb = math.sqrt(sum(v * v for v in qb.values()))
    if na == 0 or nb == 0:
        return 1.0
    return 1.0 - dot / (na * nb)


# --------------------------------------------------------------------------- #
# Write-back gate policies: (record) -> bool   (True = allowed into memory)
# --------------------------------------------------------------------------- #
def gate_store_everything(record: Dict) -> bool:
    """EHR / QA policy: every finished record is stored (no user judgement)."""
    return True


def gate_only_correct(record: Dict) -> bool:
    """A natural defence: only store records whose answer matched ground truth.

    Under this gate a *malicious* (Caesar-shifted, therefore wrong) record is
    rejected -- which is exactly why the attack needs the gate to be absent or
    forgeable.
    """
    return record["answer"] == record["groundtruth"]


# --------------------------------------------------------------------------- #
@dataclass
class MemoryAgent:
    llm: object
    n_shots: int = 3
    retrieval: Callable[[str, Dict], float] = edit_distance_retrieval
    write_back_gate: Callable[[Dict], bool] = gate_store_everything
    memory: List[Dict] = field(default_factory=list)

    def retrieve(self, question: str) -> List[Dict]:
        if not self.memory:
            return []
        scored = sorted(self.memory, key=lambda m: self.retrieval(question, m))
        return scored[: min(self.n_shots, len(scored))]

    def run(
        self,
        item: Dict,
        indication: Optional[str] = None,
        allow_write: bool = True,
    ) -> Dict:
        """Process one query. Returns the produced record (and may store it)."""
        # The query actually submitted is (benign question + indication prompt).
        # Faithful to QA/main.py, BOTH retrieval and the stored record key off
        # this submitted text -- so same-template malicious records (which share
        # the long question prefix) become each other's nearest neighbours,
        # which is what lets PSS bootstrap the weak/empty indication steps.
        submitted_question = item["question"]
        if indication:
            submitted_question = f"{item['question']} {indication}"

        retrieved = self.retrieve(submitted_question)
        demos = [Demo(m["question"], m["thought"], m["answer"]) for m in retrieved]

        out = self.llm.answer(
            question=submitted_question,
            options=item["options"],
            ground_truth=item["groundtruth"],
            demos=demos,
            indication=indication,
        )

        stored_question = submitted_question

        record = {
            "id": item["id"],
            "question": stored_question,
            "options": item["options"],
            "thought": out.get("Thought", ""),
            "answer": out.get("Answer", "None"),
            "groundtruth": item["groundtruth"],
            "n_retrieved": len(retrieved),
            "n_retrieved_malicious": sum(
                1 for m in retrieved if "detect the unsafe word" in m["thought"].lower()
            ),
        }

        if allow_write and self.write_back_gate(record):
            self.memory.append(record)
            record["_stored"] = True
        else:
            record["_stored"] = False
        return record
