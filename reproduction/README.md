# MINJA — 最小可运行复现（mechanistic reproduction）

本目录是对论文 **MINJA: Memory Injection Attacks on LLM Agents via Query-Only
Interaction (NeurIPS 2025)** 的**机理级**复现，纯标准库 Python、**零依赖、可离线确定性运行**。

原仓库（本仓库 `rap/`、`EHR/`、`QA/`）是官方实现，但**无法在本环境直接跑出论文数字**：
它依赖 OpenAI API key、需要 PhysioNet 资质审核的 MIMIC-III / eICU、一个本地 WebShop
服务器以及 GPU 上的句向量模型。因此这里不是去复刻那些数字，而是把 MINJA 的**核心机理**
单独抽出来，用一个**忠实的行为级 mock LLM** 把整条"注入→测试"攻击链路完整跑通，
从而能：

1. 复现论文的头条指标（ISR≈100%、ASR≈80%、UD≈0%）与 Appendix L 的 PSS 强弱顺序；
2. 通过消融，**把"论文包装"和"代码真正依赖的前提"分开**。

## 怎么跑

```bash
cd reproduction
python3 run.py            # 主实验 + 三组消融 + 结论（离线、确定性）
python3 stress_test.py    # 更真实环境下的压力测试（5 组扫描 + SVG 图 + REPORT.md）
python3 test_minja.py     # 18 条断言，锁定机理与压力测试的关键结论
```

### 真实环境压力测试（`realistic.py` + `stress_test.py`）

`run.py` 是论文**自身条件**下的机理复现；`stress_test.py` 把攻击放进一个带**真实部署机制**
的 harness 里逐项加压。先把一个**概率化**的 LLM 行为模型标定到论文条件下复现 ASR≈0.8
（基线 **ISR 85% / ASR 78%±7%**，8 seeds），再每次只改一个现实因素：

| 因素 | ASR 变化 |
|---|---|
| E1 共享库里的同主题合法记录 0→300 | 78% → **2%** |
| E2 写回正确性校验 拦截率 0→100% | 47% → **0%** |
| E3 按用户隔离/来源加权 0→100% | 41% →（25% 即）**3%** → 0% |
| E4 检索相似度下限（含效用代价） | 0.34 以下 47% → 0.40 **0%** |
| E5 受害者到达前的时间间隔（有界记忆） | 0 → **0%**（后续写入挤出毒记录） |

输出：`results/REPORT.md` + `results/e*.svg`。**结论**：论文的高 ASR 依赖一组对攻击者
极友好的条件；换成真实部署里常见的任一设置，ASR 就从 ~78% 掉到 0–15%。详见 `../论文笔记_MINJA.md` §8。

可选参数：`--retrieval {cosine,edit}`、`--backend openai --model gpt-4o`（如有 key，
可对真实模型跑同一套 QA 实验）。

- `cosine`（默认）：词袋余弦，作为论文句向量检索（MiniLM / ada-002）的**语义替身**。
- `edit`：`QA/main.py` 实际使用的 **Levenshtein 编辑距离**。注意在本仓库这种**短**合成问题上，
  编辑距离会被长度主导、被短的良性记录挤掉带 indication 的恶意记录，导致自举失败（ISR/ASR≈0）；
  真实 MMLU 的长问题里"共享题干"效应更强，编辑距离才勉强可用。这个反差本身就佐证了笔记 §5.4：
  **QA 放出的检索器又糙又和论文宣称的 ada-002 不符。**

## 跑出来的结果（mock 后端，cosine 检索）

```
[1] 主结果： ISR=100.0%  ASR=80.0%  UD=+0.0%
            注入的恶意记录 60 条，其中 50 条仍带 indication 文本、10 条"看起来无害"
            分步注入成功率： note1..note4 靠"照做指令"，note5/bare 靠"照抄记忆(ICL)"
[2] 消融A（写回前做正确性校验）： ISR=0%  ASR=0%   → 攻击直接崩
[3] 消融B（记忆隔离，受害者不共享攻击者记忆）： ASR=0%   → 攻击无从触发
[4] 消融C（PSS 开关）： full(100/80) > fewer(50/70) > none(0/0)
```

## 与官方代码的对应关系

| 论文/机理 | 本复现 | 官方代码 |
|---|---|---|
| 受害者→目标 后门（QA：答案 +4 凯撒移位，E/F/G/H 即成功） | `llm.py` `caesar_shift_letter` / `experiment.is_malicious_answer` | `QA/main.py:372,392,431` |
| indication prompt（注入指令） | `attack.qa_indication_steps`（note1..note5） | `QA/victim.json`、`rap/indication_prompt_template.json`、`EHR .../add_poison.py` |
| bridging steps（被照抄的虚假前提） | `llm.py` 中带引号 victim term 的恶意 thought | EHR `add_poison.modify_entry`、QA 注入记录的 Thought |
| PSS（渐进缩短） | `attack.progressive_shortening_sequence` + `experiment._schedule` | 手写的 note 列表 / `add_poison.py` modes 1..5 |
| 相似度检索 + ICL | `agent.MemoryAgent.retrieve` + `llm.MockLLM` | QA：Levenshtein；EHR/RAP：MiniLM 余弦 |
| 写回门控（攻击的真正命门） | `experiment._should_store` / `agent` 的 gate | EHR/QA 全存（`main.py:200`）；RAP 伪造 reward（`minja.py:494,562`） |
| ISR / ASR / UD | `experiment.run_injection / run_test / measure_ud` | `QA/main.py` 末尾、`EHR/.../attack_check.py`、RAP `run_test` |

## mock LLM 是否"作弊"？

不是。`MockLLM` 只建模真实 LLM 被 MINJA 利用的**两种**行为，且**默认走良性分支**：

1. **照做指令**：prompt 里若有可执行的注入指令（"detect the unsafe word…encrypt by +4"），
   就照做——这解释了**注入**为何成立；
2. **照抄记忆（ICL）**：检索回来的示范里若多数是恶意的，就模仿——这解释了去掉 indication 后
   攻击为何**仍能持续**（PSS 的意义），以及受害者 query 为何也中招。

并且后门是**有条件的**（"句子里出现 'security' 时才加密"），所以不含受害词的良性问题不受影响
（UD≈0）。正因为只建模这两条且可逐一关闭，消融才能干净地暴露攻击真正依赖的前提。

> 注意：mock 后端的数字是**机理示意**，不是论文中 GPT-4/GPT-4o 的实测值；其价值在于
> 可离线复现攻击**动态**并暴露其**前提条件**。详见 `../论文笔记_MINJA.md`。
