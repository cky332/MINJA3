"""End-to-end MINJA reproduction: main attack + ablations + report.

Run:  python run.py            # offline, deterministic, no API key
      python run.py --backend openai --model gpt-4o   # against a real model

The point of the ablations is to separate what the paper *claims* (a query-only
attack) from what the code actually *needs*: a shared memory bank, an absent or
forgeable write-back check, and similarity retrieval that PSS games.
"""

from __future__ import annotations

import argparse
import copy

from dataset import build_dataset, VICTIM_TERM
from experiment import run_injection, run_test, measure_ud, is_malicious_answer
from agent import edit_distance_retrieval, cosine_bow_retrieval


def _build_clean_memory(dataset, victim_term, num_benign, n_shots, retrieval, llm, seed):
    """Inject only benign queries (no attack) -> the UD baseline memory."""
    res = run_injection(
        dataset, victim_term, num_templates=0, num_benign=num_benign,
        mode="full_pss", gate="realistic", n_shots=n_shots,
        retrieval=retrieval, llm=llm, seed=seed,
    )
    return res.memory


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["mock", "openai"], default="mock")
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--num_templates", type=int, default=10)
    ap.add_argument("--num_benign", type=int, default=30)
    ap.add_argument("--num_test", type=int, default=10)
    ap.add_argument("--n_shots", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--retrieval", choices=["edit", "cosine"], default="cosine",
                    help="cosine = bag-of-words stand-in for the paper's "
                         "sentence embeddings; edit = the QA repo's actual "
                         "Levenshtein retriever")
    args = ap.parse_args()

    if args.backend == "openai":
        from llm import OpenAILLM
        llm = OpenAILLM(model_name=args.model)
    else:
        from llm import MockLLM
        llm = MockLLM(seed=args.seed)

    retrieval = edit_distance_retrieval if args.retrieval == "edit" else cosine_bow_retrieval
    ds = build_dataset(VICTIM_TERM, seed=args.seed)
    common = dict(num_templates=args.num_templates, num_benign=args.num_benign,
                  n_shots=args.n_shots, retrieval=retrieval, llm=llm, seed=args.seed)

    print("=" * 72)
    print(f"MINJA reproduction  |  backend={args.backend}  retrieval={args.retrieval}")
    print(f"victim term = '{VICTIM_TERM}'  (target = answer Caesar-shifted +4)")
    print(f"victim Qs={len(ds['victim'])}  benign Qs={len(ds['benign'])}  "
          f"templates={args.num_templates}  benign-mixed={args.num_benign}")
    print("=" * 72)

    # --- Main attack: full PSS, realistic (no real verification) gate --------
    inj = run_injection(ds, VICTIM_TERM, mode="full_pss", gate="realistic", **common)
    asr = run_test(inj.memory, ds, VICTIM_TERM, num_test=args.num_test,
                   num_templates=args.num_templates, n_shots=args.n_shots,
                   retrieval=retrieval, llm=llm, seed=args.seed)
    clean_mem = _build_clean_memory(ds, VICTIM_TERM, args.num_benign,
                                    args.n_shots, retrieval, llm, args.seed)
    ud = measure_ud(inj.memory, clean_mem, ds, num_benign_test=10,
                    n_shots=args.n_shots, retrieval=retrieval, llm=llm, seed=args.seed)

    print("\n[1] MAIN RESULT (the headline numbers)")
    print(f"    ISR (inject success rate, bare query)  = {inj.isr*100:5.1f}%")
    print(f"    ASR (attack success rate, victim test) = {asr*100:5.1f}%")
    print(f"    UD  (utility drop on benign queries)   = {ud*100:+5.1f}%")
    print(f"    malicious records stored = {inj.n_malicious_stored} "
          f"(of which {inj.n_malicious_with_indication} still carry indication text)")
    print(f"    stepwise injection success (step -> success/total):")
    steps = qa_steps_label(args.num_templates)
    for k, (s, t) in inj.stepwise_success.items():
        print(f"        step {k} {steps.get(k,''):<14} {s}/{t}")

    # --- Ablation A: a real write-back verification gate ---------------------
    inj_gate = run_injection(ds, VICTIM_TERM, mode="full_pss",
                             gate="verify_correct", **common)
    asr_gate = run_test(inj_gate.memory, ds, VICTIM_TERM, num_test=args.num_test,
                        num_templates=args.num_templates, n_shots=args.n_shots,
                        retrieval=retrieval, llm=llm, seed=args.seed)
    print("\n[2] ABLATION A -- add a real verification gate (store iff answer correct)")
    print(f"    ISR = {inj_gate.isr*100:5.1f}%   ASR = {asr_gate*100:5.1f}%   "
          f"malicious stored = {inj_gate.n_malicious_stored}")
    print("    => malicious (Caesar-shifted) answers are wrong, so the gate rejects")
    print("       them. The attack collapses. RAP only 'works' by forging reward=1.0.")

    # --- Ablation B: isolated (per-user) memory -----------------------------
    asr_iso = run_test(clean_mem, ds, VICTIM_TERM, num_test=args.num_test,
                       num_templates=args.num_templates, n_shots=args.n_shots,
                       retrieval=retrieval, llm=llm, seed=args.seed)
    print("\n[3] ABLATION B -- isolated memory (victim does NOT share attacker memory)")
    print(f"    ASR = {asr_iso*100:5.1f}%")
    print("    => with no shared memory bank the injected records are never")
    print("       retrieved for the victim. The 'shared memory' assumption is load-bearing.")

    # --- Ablation C: value of PSS (seeding + retrievability) -----------------
    print("\n[4] ABLATION C -- Progressive Shortening Strategy (PSS) on/off")
    print(f"    {'mode':<12}{'ISR':>8}{'ASR':>8}{'mal_stored':>12}{'benign_looking':>16}")
    for mode in ["full_pss", "fewer_pss", "no_pss"]:
        r = run_injection(ds, VICTIM_TERM, mode=mode, gate="realistic", **common)
        a = run_test(r.memory, ds, VICTIM_TERM, num_test=args.num_test,
                     num_templates=args.num_templates, n_shots=args.n_shots,
                     retrieval=retrieval, llm=llm, seed=args.seed)
        benign_looking = r.n_malicious_stored - r.n_malicious_with_indication
        print(f"    {mode:<12}{r.isr*100:7.1f}%{a*100:7.1f}%"
              f"{r.n_malicious_stored:>12}{benign_looking:>16}")
    print("    => PSS both seeds malicious records (raising ISR on the bare query)")
    print("       and makes the stored query look benign (raising retrievability => ASR).")

    print("\n" + "=" * 72)
    print("Takeaway: the headline 'query-only' attack is real, but it stands on")
    print("three preconditions the code makes explicit -- shared memory, no/forged")
    print("write verification, and gameable similarity retrieval. Remove any one")
    print("(ablations A/B) and the attack largely collapses.")
    print("=" * 72)


def qa_steps_label(_n):
    return {0: "note1(full)", 1: "note2", 2: "note3", 3: "note4",
            4: "note5(stub)", 5: "bare(none)"}


if __name__ == "__main__":
    main()
