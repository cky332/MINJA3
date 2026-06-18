"""Stress-test MINJA under realistic deployment conditions.

Each experiment fixes a paper-like baseline and varies ONE realistic factor,
reporting ASR (and ISR) as mean +/- std over several seeds. Calibration: the
baseline reproduces the paper's ~0.8 ASR; every realistic factor degrades it.

Run:  python3 stress_test.py
Outputs: console tables + ASCII bars, SVG charts and REPORT.md in results/.
"""

from __future__ import annotations

import os
from statistics import mean, pstdev

from dataset import build_scaled, gen_benign_questions
from realistic import RealisticLLM, RealisticMemory, prefill_benign, run_attack

SEEDS = list(range(8))
N_TEST = 18  # matches the paper's repeated-experiment sample size (Appendix K)
VICTIM = "security"
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def run_point(n_benign=10, victim_own_n=0, mem_kw=None, llm_kw=None,
              post_n=0, k=5, seeds=SEEDS):
    mem_kw = mem_kw or {}
    llm_kw = llm_kw or {}
    isrs, asrs, mals = [], [], []
    for s in seeds:
        ds = build_scaled(n_templates=10, n_test=N_TEST, n_benign=n_benign, seed=s)
        mem = RealisticMemory(**mem_kw)
        mem.seed_rng(s)
        prefill_benign(mem, ds["benign"], seed=s)
        own = gen_benign_questions(victim_own_n, seed=500 + s) if victim_own_n else None
        post = gen_benign_questions(post_n, seed=1000 + s) if post_n else None
        llm = RealisticLLM(seed=s, **llm_kw)
        r = run_attack(victim_term=VICTIM, templates=ds["templates"],
                       victim_test=ds["victim_test"], mem=mem, llm=llm, k=k,
                       post_inject_benign=post, victim_own=own)
        isrs.append(r["isr"]); asrs.append(r["asr"]); mals.append(r["n_malicious_stored"])
    return {
        "isr": mean(isrs), "asr": mean(asrs), "asr_std": pstdev(asrs),
        "mal": mean(mals),
    }


def bar(v, width=28):
    return "#" * int(round(v * width)) + "." * (width - int(round(v * width)))


def table(title, rows, xlabel):
    """rows: list of (xval_str, result_dict). Prints a table + ASCII ASR bars."""
    print(f"\n### {title}")
    print(f"  {xlabel:<22}{'ISR':>6}{'ASR':>7}{'+/-':>6}{'mal':>6}   ASR")
    for x, r in rows:
        print(f"  {x:<22}{r['isr']*100:5.0f}%{r['asr']*100:6.0f}%"
              f"{r['asr_std']*100:5.0f}%{r['mal']:6.0f}   {bar(r['asr'])}")


# --------------------------------------------------------------------------- #
def svg_line(title, xlabels, ys, yerrs, baseline, fname, ylabel="ASR"):
    W, H = 560, 320
    ml, mr, mt, mb = 60, 20, 40, 60
    pw, ph = W - ml - mr, H - mt - mb
    n = len(xlabels)
    xs = [ml + (pw * (i + 0.5) / n) for i in range(n)]

    def Y(v):
        return mt + ph * (1 - max(0.0, min(1.0, v)))

    p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'font-family="sans-serif" font-size="12">',
         f'<rect width="{W}" height="{H}" fill="white"/>',
         f'<text x="{W/2}" y="20" text-anchor="middle" font-size="14" '
         f'font-weight="bold">{title}</text>']
    # axes + gridlines
    for g in range(0, 11, 2):
        v = g / 10
        y = Y(v)
        p.append(f'<line x1="{ml}" y1="{y:.1f}" x2="{W-mr}" y2="{y:.1f}" '
                 f'stroke="#eee"/>')
        p.append(f'<text x="{ml-8}" y="{y+4:.1f}" text-anchor="end" '
                 f'fill="#666">{v:.1f}</text>')
    p.append(f'<text x="18" y="{mt+ph/2}" text-anchor="middle" fill="#444" '
             f'transform="rotate(-90 18 {mt+ph/2})">{ylabel}</text>')
    # baseline reference
    yb = Y(baseline)
    p.append(f'<line x1="{ml}" y1="{yb:.1f}" x2="{W-mr}" y2="{yb:.1f}" '
             f'stroke="#bbb" stroke-dasharray="4 3"/>')
    p.append(f'<text x="{W-mr}" y="{yb-4:.1f}" text-anchor="end" fill="#999">'
             f'paper-like baseline {baseline:.2f}</text>')
    # x labels
    for i, xl in enumerate(xlabels):
        p.append(f'<text x="{xs[i]:.1f}" y="{H-mb+20}" text-anchor="middle" '
                 f'fill="#444">{xl}</text>')
    # error bars + line + points
    pts = " ".join(f"{xs[i]:.1f},{Y(ys[i]):.1f}" for i in range(n))
    for i in range(n):
        x, y = xs[i], Y(ys[i])
        e0, e1 = Y(ys[i] - yerrs[i]), Y(ys[i] + yerrs[i])
        p.append(f'<line x1="{x:.1f}" y1="{e1:.1f}" x2="{x:.1f}" y2="{e0:.1f}" '
                 f'stroke="#c0392b"/>')
    p.append(f'<polyline points="{pts}" fill="none" stroke="#c0392b" '
             f'stroke-width="2"/>')
    for i in range(n):
        p.append(f'<circle cx="{xs[i]:.1f}" cy="{Y(ys[i]):.1f}" r="3.5" '
                 f'fill="#c0392b"/>')
    p.append("</svg>")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(os.path.join(RESULTS_DIR, fname), "w") as f:
        f.write("\n".join(p))


# --------------------------------------------------------------------------- #
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("=" * 72)
    print("MINJA under realistic conditions  (ASR = mean over %d seeds)" % len(SEEDS))
    print("=" * 72)

    base = run_point(n_benign=0, victim_own_n=0)
    baseline = base["asr"]
    print(f"\nPAPER-LIKE BASELINE (no on-topic competition, no defenses): "
          f"ISR={base['isr']*100:.0f}%  ASR={base['asr']*100:.0f}%"
          f"+/-{base['asr_std']*100:.0f}%")

    report = ["# MINJA in realistic environments — stress-test report\n",
              f"Baseline (paper-like: empty/sparse memory, no defenses): "
              f"**ISR {base['isr']*100:.0f}% / ASR {base['asr']*100:.0f}%"
              f"±{base['asr_std']*100:.0f}%** over {len(SEEDS)} seeds — reproduces the "
              "paper's ~0.8 band. The dashed line in each chart marks this "
              "attacker's-best-case. Each section changes ONE realistic factor.\n"]

    def emit(title, xlabel, points, fname, narrative):
        rows = [(x, run_point(**kw)) for x, kw in points]
        table(title, rows, xlabel)
        svg_line(title, [x for x, _ in rows], [r["asr"] for _, r in rows],
                 [r["asr_std"] for _, r in rows], baseline, fname)
        report.append(f"\n## {title}\n")
        report.append(f"![chart]({fname})\n")
        report.append("| %s | ISR | ASR | ±std | mal stored |" % xlabel)
        report.append("|---|---|---|---|---|")
        for x, r in rows:
            report.append(f"| {x} | {r['isr']*100:.0f}% | {r['asr']*100:.0f}% | "
                          f"{r['asr_std']*100:.0f}% | {r['mal']:.0f} |")
        report.append("\n" + narrative + "\n")
        return rows

    # E1: memory at real scale (on-topic legitimate traffic)
    emit("E1. On-topic legitimate traffic in shared bank", "n_legit",
         [(str(n), {"n_benign": n, "victim_own_n": 0}) for n in [0, 10, 30, 100, 300]],
         "e1_scale.svg",
         "The paper's memory is tiny and has almost no records that legitimately "
         "mention the victim term. Real banks accumulate many on-topic legit "
         "records. As they grow, the victim query's top-k is less and less "
         "dominated by poison, so ASR falls — flooding memory does not survive "
         "realistic on-topic traffic AT A FIXED BUDGET. (Honest caveat: an "
         "*adaptive* attacker who simply injects proportionally more recovers ASR "
         "— dilution is a linear cost, not a wall; see adversarial.py / REPORT3 A1. "
         "What turns the cost into a wall is rate-limiting the budget, A2.)")

    # E2: write-time verification (the cheapest, strongest defense)
    emit("E2. Write-time verification (catch malicious record)", "catch_rate",
         [(f"{int(p*100)}%", {"mem_kw": {"p_verify": p}})
          for p in [0.0, 0.25, 0.5, 0.75, 1.0]],
         "e2_verify.svg",
         "The cheapest defense and the paper's own (bypassed) RAP assumption. "
         "Checking what gets written back drives ASR down monotonically — every "
         "malicious record is, by construction, a wrong answer (a wrong patient / "
         "wrong item / shifted answer), so an independent check rejects it.")

    # E3: per-user provenance / isolation
    emit("E3. Per-user memory isolation (provenance)", "isolation",
         [(f"{int(i*100)}%", {"victim_own_n": 3, "mem_kw": {"isolation": i}})
          for i in [0.0, 0.25, 0.5, 0.75, 1.0]],
         "e3_isolation.svg",
         "MINJA's one hard assumption is a shared bank. Down-weighting records "
         "written by *other* users (and trusting the victim's own history) removes "
         "the attacker's writes from the victim's retrieval; near-full isolation "
         "drives ASR to zero.")

    # E4: retrieval similarity floor
    emit("E4. Retrieval similarity floor", "min_sim",
         [(f"{t}", {"mem_kw": {"retrieval_threshold": t}})
          for t in [0.0, 0.2, 0.30, 0.34, 0.40]],
         "e4_threshold.svg",
         "A held-out victim query shares only the victim term with the poison "
         "(PSS stripped the rest), so the match is weak (cos~0.33). A floor above "
         "that removes the poison from the demo set — but it also removes "
         "legitimate on-topic records, so a naive floor trades utility for safety "
         "(an honest limitation, not a free win).")

    # E5: temporal dilution (bounded memory + later traffic)
    emit("E5. Temporal gap before victim arrives (bounded memory)", "later_writes",
         [(str(d), {"post_n": d, "mem_kw": {"capacity": 64}})
          for d in [0, 25, 50, 100, 300]],
         "e5_decay.svg",
         "With a bounded memory, other users' later writes evict the injected "
         "records (FIFO). The attacker must strike just before the victim — the "
         "paper concedes this, and under real traffic the window is small.")

    with open(os.path.join(RESULTS_DIR, "REPORT.md"), "w") as f:
        f.write("\n".join(report))

    print("\n" + "=" * 72)
    print(f"charts + REPORT.md written to {RESULTS_DIR}/")
    print("Summary: under the paper's conditions ASR≈%.0f%%; each realistic factor"
          % (baseline * 100))
    print("(scale, dedup, retrieval floor, write check, provenance, time) drives it down.")
    print("=" * 72)


if __name__ == "__main__":
    main()
