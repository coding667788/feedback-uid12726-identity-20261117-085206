# 离线安全事件重建工具（偏序重建与冲突定位）

从三台**模拟主机**的签名事件文件出发，重建事件的 UTC 时间区间、可证的先后偏序、
矛盾证据的最小不可满足核心与确定性拓扑展示。全程离线：不联网、不接触真实设备、
只读原始文件。

```
python -m solution --input cases.json --output result.json
python -m unittest discover -s tests -v
```

* 运行环境：Windows / Python 3.12 / 纯 CPU / 仅标准库（Ed25519 自带实现，见
  [为什么不需要 cryptography](#为什么不需要-cryptography)）。
* 样例与测试数据全部由本项目内的模拟器生成，固定种子可重放。
* 所有操作局限在项目目录内（运行时临时文件写入 `.runtime-tmp/`）。

---

## 1. 交付物

| 路径 | 内容 |
| --- | --- |
| `solution/` | 实现（包 `solution`，入口 `python -m solution`） |
| `tools/sim_agent.py` | 模拟主机采集代理：用固定密钥产生**已签名**的事件文件 |
| `tools/make_samples.py` | 生成 `samples/` 下的样例与 `cases.json`（确定性，可重放） |
| `samples/main/` | 三主机、两 boot 的综合样例，含清单、封印、重复采集、篡改、ID 冲突 |
| `samples/scenarios/` | 验收场景的聚焦样例（6 个目录）：`clock_rollback`、`reboot`、`duplicate`、`send_recv`、`overlap`、`core_minimal` |
| `tests/` | 169 个自动化测试，断言具体结果/状态/证据 |
| `README.md` | 本文档：schema、错误码、语义、算法与设计取舍 |

模块划分（`solution/`）：

| 模块 | 职责 |
| --- | --- |
| `sources.py` | 只读打开、两次读取、按行切字节区间 |
| `records.py` | 记录 schema 校验、规范化 JSON、签名载荷 |
| `collect.py` | 采集成结点、签名四态、窄口径去重、ID 冲突 |
| `manifest.py` / `integrity.py` | 清单与封印、规范 JSON、SHA-256/HMAC |
| `constraints.py` | 差分约束求解、全对最紧界、最小核心 |
| `model.py` | 证据 → 约束（唯一做这个映射的地方） |
| `analysis.py` | 求值、偏序、窗口、核心渲染、拓扑展示、反事实视图 |
| `render.py` | 事件图与 Graphviz DOT |
| `verify.py` | 三个独立可行性 oracle 与见证校验 |
| `pipeline.py` / `cli.py` | 编排、状态汇总、退出码、原子写结果 |

---

## 2. 快速开始

```bash
# 1. 生成样例（已提交，重跑应产生逐字节相同的文件）
python tools/make_samples.py

# 2. 综合样例：三主机 / 两 boot / 清单封印 / 重复 / 篡改 / ID 冲突
set EVIDENCE_SEAL_KEY=sample-only-seal-key-not-a-secret   # cmd
EVIDENCE_SEAL_KEY=sample-only-seal-key-not-a-secret python -m solution \
    --input samples/main/cases.json --output .runtime-tmp/out/main.json

# 3. 各验收场景
python -m solution --input samples/scenarios/overlap/cases.json       --output .runtime-tmp/out/overlap.json
python -m solution --input samples/scenarios/reboot/cases.json        --output .runtime-tmp/out/reboot.json
python -m solution --input samples/scenarios/clock_rollback/cases.json --output .runtime-tmp/out/rollback.json
python -m solution --input samples/scenarios/send_recv/cases.json     --output .runtime-tmp/out/sendrecv.json
python -m solution --input samples/scenarios/duplicate/cases.json     --output .runtime-tmp/out/duplicate.json
python -m solution --input samples/scenarios/core_minimal/cases.json  --output .runtime-tmp/out/core.json

# 4. 测试（上面的结果默认写到 .runtime-tmp/out/，已在 .gitignore 中）
python -m unittest discover -s tests -v
```

### 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 分析完成，约束系统可行（`status` 为 `ok` / `conflict` / `partial`） |
| 1 | 分析完成但约束矛盾（`status` = `contradiction`，含最小不可满足核心） |
| 2 | 输入无法处理（致命错误，`status` = `error`，结果中有一条诊断） |
| 3 | 结果文件无法写入（`E_OUTPUT_WRITE`） |

命令行开关：`--check`（额外要求内部交叉校验通过，否则退出码 ≥1）、`--quiet`
（不打印摘要行）。

---

## 3. 输入

### 3.1 `cases.json`（schema `evidence-reconstruction/cases-v1`）

```json
{
  "schema": "evidence-reconstruction/cases-v1",
  "case_id": "sample-main",
  "seed": 20260101,
  "drift_ppm": 0,
  "manifest": "manifest.json",
  "sources": [
    {"id": "host_web01_b1", "path": "host_web01_b1.jsonl"},
    "host_db01_b1.jsonl"
  ]
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `schema` | 否 | 缺省即上面的值；其它值报 `E_INPUT_SCHEMA` |
| `case_id` | 否 | 仅回显 |
| `seed` | 否 | 整数，仅回显；样例用它声明可重放性 |
| `drift_ppm` | 否 | 非负整数，默认 0。同一 boot 内按单调计时推算经过时间时允许的相对误差（见 §5.2） |
| `manifest` | 否 | 采集清单路径，相对 `cases.json` 所在目录 |
| `sources` | 是 | 字符串或 `{"id","path"}`。`id` 缺省取文件名主干；`id` 必须唯一 |

源路径必须位于 `cases.json` 所在目录树内，否则 `E_PATH_OUTSIDE_ROOT`（防止把结果
写成对任意路径的读取探针）。

### 3.2 事件文件（JSON Lines，UTF-8）

一行一个 JSON 对象，空行忽略。三类记录：

```jsonc
{"type":"host_key","host":"web01","public_key":"<64 hex>"}
{"type":"boot","host":"web01","boot_id":"b1",
 "calibration":{"offset_lo_ms":1900,"offset_hi_ms":2100,"mono_earliest_ns":1000000000000},
 "follows":{"host":"web01","boot_id":"b0"},   // 可选：声明的重启先后
 "drift_ppm":0,                                // 可选：覆盖 cases.json 的默认值
 "sig":"<128 hex>"}
{"type":"event","id":"web01-b1-002","host":"web01","boot_id":"b1","seq":2,
 "mono_ns":1020000000000,
 "wall":"2026-01-01T01:00:20Z",
 "kind":"send","message_id":"m-101",
 "sig":"<128 hex>"}
```

| 字段 | 约束 |
| --- | --- |
| `id` | 非空字符串，不得以 `@` 开头（`@epoch` 是保留节点名） |
| `seq` | 非负整数，**仅在同一 boot 内**有意义 |
| `mono_ns` | 整数，单调计时读数（纳秒）；**不跨 boot 比较** |
| `wall` | RFC 3339；`T`/`t`/空格分隔，`Z`/`z` 或 `±HH:MM`，小数最多 9 位；拒绝闰秒 `:60` 与非 ASCII 数字 |
| `kind` | `send` / `recv` / `local`；`send`/`recv` 必须带非空 `message_id`，`local` 不得带 |
| `calibration` | `offset_*_ms` 必须是整数毫秒，`lo ≤ hi`；`mono_earliest_ns` 可选，作为证据保存但不产生时间约束（见 §5.2） |
| `follows` | `{"host","boot_id"}` 或同主机内的 `boot_id` 字符串，可选 |

**签名**：`sig` 覆盖"去掉 `sig` 成员后的规范化 JSON"——键排序、无空白、UTF-8。
因此文件里的空格与成员顺序可自由变化，但只要值改动（含时间戳、序号）签名即失效。
`host_key` 记录不签名（它是本批次信任根，自身靠内容比对）。

### 3.3 采集清单（schema `evidence-collection/manifest-v1`）

```json
{
  "schema": "evidence-collection/manifest-v1",
  "case_id": "sample-main",
  "collected_at": "2026-01-01T03:00:00Z",
  "sources": [{"id":"host_web01_b1","path":"host_web01_b1.jsonl",
               "sha256":"<64 hex>","bytes":1234,"host":"web01","role":"event-log"}],
  "seal": "hmac-sha256:<64 hex>"
}
```

* `sources[].sha256` / `bytes` 与实读比对，不一致即 `E_MANIFEST_HASH_MISMATCH`。
* `seal` 是清单主体（除 `seal` 外全部字段）的 HMAC-SHA256，密钥取自环境变量
  `EVIDENCE_SEAL_KEY`。**密钥刻意不放在项目里**：没有密钥时工具只说"带封印但未校验"
  （`seal_state = unverified_no_key`），绝不假装校验通过。样例为了可复现使用了一个
  公开的示例密钥（`samples/main/keys.json` 中注明不可用于真实场景）。
* 清单登记但本次未分析的文件报 `E_MANIFEST_EXTRA_ENTRY`；反过来报
  `E_MANIFEST_MISSING_ENTRY`。

清单是**索引**，不是真实性证明；单条记录的真实性来自主机 Ed25519 签名。两者的边界
在 README 与 `consistency` 字段里都写清楚了。

---

## 4. 输出（schema `evidence-reconstruction/result-v1`）

顶层键固定为：

```jsonc
{
  "schema": "evidence-reconstruction/result-v1",
  "tool": {"name":"solution","version":"1.0.0"},
  "case": {"case_id":..., "cases_file":..., "seed":..., "drift_ppm":..., "resolution_ns":1},
  "status": "ok | partial | conflict | contradiction | error",
  "sources":   [ {"id","path","sha256","bytes","manifest_sha256","manifest_bytes","manifest_match"} ],
  "manifest":  {"path","schema","case_id","collector","collected_at","notes","sources","seal","seal_state"},
  "integrity": {"sources_unchanged","first_read","last_read","manifest_digest","manifest_seal_state","note"},
  "models":    {"boots","messages","constraints","excluded_events"},
  "timeline":  [ 见 §4.1 ],
  "windows":   [ 见 §4.2 ],
  "order":     { 见 §4.3 },
  "graph":     { 见 §4.4 },
  "conflicts": [ 见 §4.5 ],
  "unsat_cores": [ 见 §4.6 ],
  "quarantine": null | { 见 §4.7 },
  "cross_check": { 见 §4.8 },
  "diagnostics": [ {"code","message","source?","line?","byte_start?","byte_end?","detail?"} ],
  "errors": ["去重排序后的诊断码"]
}
```

`status`（按此优先级判定：矛盾 > 致命错误 > 证据冲突 > 部分可用 > ok）：

| 值 | 含义 |
| --- | --- |
| `ok` | 可行，无冲突证据（字节一致的重复采集不算"证据问题"） |
| `partial` | 可行，但有削弱证据的结构/真实性问题：`E_SIG_INVALID`、`E_SIG_MISSING`、`E_SIG_UNVERIFIED`、`E_BOOT_MISSING`、`E_DANGLING`、`E_MESSAGE_PAIR`、`E_SEQ_DUP`、`E_MONO_ANOMALY`、`E_REBOOT_ORDER`、`E_SEAL_INVALID`、`E_SEAL_UNVERIFIED`、`E_MANIFEST_*`（以 `solution/pipeline.py` 的 `PARTIAL_CODES` 为准） |
| `conflict` | 可行，但存在"同 ID 异内容"的证据冲突 |
| `contradiction` | 约束不可满足，已给出最小不可满足核心 |
| `error` | 输入无法处理 |

### 4.1 `timeline[]`

```jsonc
{
  "id":"web01-b1-003","host":"web01","boot_id":"b1","seq":3,"kind":"recv",
  "message_id":"m-102",
  "wall":"2026-01-01T01:00:40Z","wall_ns":1767225640000000000,
  "mono_ns":1040000000000,
  "possible_interval":{"lo_ns":...,"hi_ns":...,"lo":"...","hi":"...","width_ns":200000000},
  "feasible_window":{...同结构 或 null...},
  "witness_t_ns":..., "witness_t":"...",
  "signature":"valid | unverified | absent",
  "occurrences":[{"source","line","byte_start","byte_end","line_sha256","line_bytes"}]
}
```

* `possible_interval` = `[wall - offset_hi, wall - offset_lo]`（闭区间），即该校准下
  事件**可能**发生的 UTC 区间——不掺任何其他证据。
* `feasible_window` = 加上全部序关系约束后求解得到的可行区间（与 possible 求交）。
  系统不可满足时为 `null`（不假装有答案）。
* `witness_t` = 求解器给出的一个可行解，便于人工核对与机器校验。
* `occurrences` 保留每次采集的源文件、1 基行号与**字节区间**（含行终止符），可直
  接 `dd`/切片复算 `line_sha256`。

`models.boots[]` 里的 `source` 用同样结构给出**定义该校准的那条 boot 记录**的位置，
因此任何时间区间的来源都能回溯到具体字节。

### 4.2 `windows[]`

```jsonc
{"id":"...","possible":{...},"feasible":{...},"narrowed":true}
```

`narrowed` 表示别的证据确实收窄了该事件的区间（例如消息因果把它推到某时刻之后）。

### 4.3 `order`

```jsonc
{
  "feasible": true,
  "event_count": 11,
  "pair_count": 55,
  "comparable_pairs": 51,
  "concurrent_pairs": 4,
  "pairwise": [
    {"a":"db01-b1-001","b":"web01-b1-002","verdict":"after","precedes":"web01-b1-002",
     "reason":"message_causality","bound_ns":-700000000,
     "bound":"t[db01-b1-001] - t[web01-b1-002] <= -700000000 ns",
     "supporting_constraints":["c0037"]},
    {"a":"jump01-b1-001","b":"web01-b1-003","verdict":"concurrent","precedes":null,
     "reason":"no_provable_order",
     "separation_bounds_ns":{"t_b_minus_t_a_upper":1200000000,"t_a_minus_t_b_upper":1200000000},
     "supporting_constraints":[]}
  ],
  "pairwise_truncated": false,
  "precedes": {"a":["..."], "...":"..."},   // a 之前的全部事件（传递闭包）
  "follows":  {"a":["..."], "...":"..."},   // a 之后的全部事件
  "concurrent": {"a":["..."], "...":"..."},
  "topological": { 见 §4.3.1 }
}
```

每个 `verdict` 都是求解器证明的结论，不是墙钟排序：

* `before`：`a` 严格早于 `b`（至少 1 ns，即 1 个分辨率单位）；
* `after`：`b` 严格早于 `a`；
* `concurrent`：两个方向都有可行解（特别地，存在 `t_a == t_b` 的可行解），
  **不得据此排唯一时间线**。`separation_bounds_ns` 给出两个方向的可行上界。

`reason` 只是给证据起名字（`message_causality`、`same_boot_sequence`、
`declared_reboot_order`、`calibration_windows_disjoint`、`transitive_constraints`），
证明本身始终是求解器给出的界。

事件数超过 256 时省略 `pairwise` 明细（`pairwise_truncated=true`），`precedes` /
`follows` / `concurrent` 仍然完整。

#### 4.3.1 `order.topological`

```jsonc
{
  "status":"ok | cycle | unavailable",
  "algorithm":"kahn",
  "tie_break":"host, boot_id, seq, id",
  "sequence":["web01-b1-002","db01-b1-001", "..."],
  "edges":[{"from":"...","to":"..."}],
  "certificate":{
    "edges_checked":11,"edges_implied":11,"edges_in_violation":[],
    "edges_backwards":[],"concurrent_pairs":4,
    "concurrent_pairs_broken_by_tie_break":4,
    "note":"a linear extension must place every concurrent pair in some order; the tie-break decides those, and only those"
  }
}
```

线性扩展是**展示**，不是"真相"：它把已证的偏序（传递简约为 11 条边）拉直，并对并
发对用一个固定键（host, boot_id, seq, id）决定先后。`certificate` 给出可机器核对的
自检结果：每条边都确由模型蕴含（`edges_in_violation` 空）、序列中没有边被反向
（`edges_backwards` 空）、被迫排序的并发对数量被如实计数。系统不可满足时
`status = "unavailable"` 而不是编造顺序。

### 4.4 `graph`（事件图）

```jsonc
{
  "nodes":[{"id":"web01-b1-002","host":"web01","boot_id":"b1","seq":2,"kind":"send",
            "message_id":"m-101","possible_interval_ns":{"lo":...,"hi":...},
            "feasible_window_ns":{"lo":...,"hi":...},"wall":"...","signature":"valid"}],
  "edges":[{"from":"@epoch","to":"web01-b1-002","kind":"wall_hi",
            "weight_ns":1767225620000000000,"constraint":"c0011",
            "events":["web01-b1-002"]},
           {"from":"web01-b1-002","to":"db01-b1-001","kind":"precedence",
            "weight_ns":-1,"constraint":null,"events":["web01-b1-002","db01-b1-001"]}],
  "edge_counts":{"boot_order":1,"message":2,"mono_elapsed":7,"precedence":11,"seq":7,"wall_hi":11,"wall_lo":11},
  "dot":"digraph evidence {
  ...
}"
}
```

* `edges` 先列证据约束（每条约束一条边，`@epoch` 显式作为端点），再列**已证偏序的
  传递简约**（`kind = "precedence"`）。系统矛盾时不会有 `precedence` 边——因为此时
  没有任何先后关系被证明。
* `dot` 是确定性的 Graphviz 文本（节点按 `host, boot_id, seq, id` 排序，边同理），
  不需要本工具的任何依赖即可渲染。并发对画成虚线双向边；仅在系统可行时绘制——
  矛盾时工具对任何一对事件都一无所知，画"并发"会是在断言它无法支持的东西。
* 签名未验证的节点在 DOT 中填充浅灰色，一眼可辨。

### 4.5 `conflicts[]`

```jsonc
{"id":"web01-b1-001","variant_count":2,
 "variants":[{"id","host","boot_id","seq","mono_ns","wall","kind","message_id",
              "content_sha256","signature","occurrences":[...]}]}
```

同一 `id` 出现**不同内容**时，每个不同内容是一个变体。规则：**不选赢家**，该 id
整体从时间线排除（`models.excluded_events` 记录原因 `E_ID_CONFLICT`），并把双方的
字节位置都留在 `variants[].occurrences` 里。内容完全一致（规范化后）的重复采集才
合并，且合并后仍保留每一次采集的行号与字节区间。

### 4.6 `unsat_cores[]`（最小不可满足核心）

```jsonc
{
  "index":1,"size":3,"constraint_ids":["c0004","c0005","c0012"],
  "minimal":true,
  "definition":"the core is unsatisfiable and, for every member c, removing c alone makes the remaining set satisfiable",
  "constraints":[{"constraint":{"id","kind","from","to","weight_ns","events","note","means"},
                  "events":[{"id","host","boot_id","seq","kind","wall","mono_ns"}]}],
  "contradiction":{"cycle":["roll-002","@epoch","roll-003"],
                   "total_weight_ns":-29800000000,
                   "requirements":["t[roll-002] >= ... ns","t[roll-003] <= ... ns",
                                   "roll-003 at least 5000000000 ns before roll-002"],
                   "explanation":"walking the cycle gives 0 <= sum(weight_ns) = ... which is impossible ..."},
  "certificate":[{"remove":"c0004","feasible_without":true}, ...]
}
```

"最小"按题面定义执行：**删掉其中任意一条约束后系统不再矛盾**（子集最小）。实现用
负环提取 + 删除法最小化，并对每个成员重新验证删除后可行；`certificate` 是这次验证的
记录，`cross_check.cores[].minimal` 是独立复核。多个互相独立的冲突会依次报告
（每轮撤回已报告的核心后重解），最多 8 个核心，超出时 `more_cores_possible=true`。

### 4.7 `quarantine`（反事实视图，不是答案）

矛盾时给出：把**核心里的序约束**（`message` / `seq` / `boot_order`）撤回后是否可行。

```jsonc
{"scope":"ordering_only","withdrawn_constraints":["c0017"],
 "withdrawn_kinds":["message"],"withdrawn_cores":[1],
 "feasible":true,"pairwise":[...],"topological":{...},"windows":{...},
 "note":"counterfactual only: ... this is not evidence that the core is wrong"}
```

若只撤序约束仍不可行，退为 `scope: "full_core"` 并整组撤回。主结果永远保持
`contradiction`；`quarantine` 明确标注为"假如这些证据被撤回会怎样"，用于回答
"除了这条消息，其余时间线是什么样"。

### 4.8 `cross_check`

```jsonc
// 可行时
{"ok":true,"bellman_ford_feasible":true,"floyd_warshall_feasible":true,
 "fourier_motzkin_feasible":true,"witness_violations":[],"tight_bound_mismatches":[],
 "method":"witness assignment check + Floyd-Warshall closure + Fourier-Motzkin elimination"}
// 矛盾时
{"ok":true,"bellman_ford_feasible":false,"floyd_warshall_feasible":false,
 "fourier_motzkin_feasible":false,
 "cores":[{"index":1,"core_infeasible":true,"fourier_motzkin_infeasible":true,
           "deletions":[{"remove":"c0004","feasible_without":true}],"minimal":true}],
 "method":"three independent solvers agree the system is infeasible, and every reported core is re-checked to be minimal"}
```

三个**独立实现**交叉验证可行性：Bellman-Ford（生产用）、Floyd-Warshall（闭包，负
对角判矛盾）、Fourier-Motzkin（消元，不建图）。可行时另外用"见证解逐条代入"与
"逐对最紧界比对"校验；矛盾时把每个核心重算一遍并复验最小性。

---

## 5. 语义与算法

### 5.1 时间模型

全部时间为整数纳秒（Unix 纪元起）。日长固定 86400 s（不引入闰秒表；输入拒绝 `:60`）。

事件 `X` 在 boot `B` 上：

```
wall_true = wall_stated - offset,   offset ∈ [offset_lo, offset_hi]   （闭区间）
possible(X) = [wall - offset_hi, wall - offset_lo]
```

### 5.2 约束（差分约束系统，Simple Temporal Problem）

每个事件一个整数变量 `t_X`（真实 UTC 纳秒），另有一个常量节点 `@epoch = 0`。
所有规则都写成 `t_v - t_u ≤ w`：

| 证据 | 约束 |
| --- | --- |
| 墙钟 + 校准 上界 | `t_X ≤ wall - offset_lo` |
| 墙钟 + 校准 下界 | `t_X ≥ wall - offset_hi` |
| （`mono_earliest_ns`） | 仅作证据展示，**不**生成约束：该锚定量并不需要：事件与 boot 起点的差值已由墙钟窗口和经过时间约束表达，额外加入只会把时钟回拨伪装成算术错误，而不是可定位的证据矛盾 |
| 同 boot 内 `seq_A < seq_B` | `t_A + 1 ns ≤ t_B` |
| 同 boot 内单调经过时间 | `t_B - t_A ≥ (mono_B - mono_A) - drift` |
| `message_id` 的发送/接收 | `t_send + 1 ns ≤ t_recv` |
| 声明的 `follows` 重启顺序 | 上一 boot 最后一个事件 + 1 ns ≤ 本 boot 第一个事件 |

* `drift = ceil(Δmono · drift_ppm / 1e6)`，默认 0（认为单调计时精确）。
* **不同 boot 的单调计时永不比较**：`mono_ns` 只出现在同一 `(host, boot_id)` 内部的
  约束里。跨 boot 的证据只有墙钟校准、消息因果与显式 `follows`。
* 同 boot 内 `mono` 变小不构造约束，只报 `E_MONO_ANOMALY`；`seq` 顺序保持不变。

可满足性等价于约束图无负环（Bellman-Ford）。可满足时，`tight[(x,y)]` 是
`t_y - t_x` 的最紧上界（Johnson 重权 + Dijkstra 全对最短路）。

由此：

```
a 严格早于 b  ⇔  tight[(b,a)] ≤ -1
两者皆非      ⇔  并发（存在 t_a = t_b 的可行解）
t_X 的可行窗口 = [ -tight[(X,@epoch)], tight[(@epoch,X)] ]
```

**只用一个方向**判断先后、绝不按墙钟排序——这正是"区间部分重叠必须保持并发"的
形式化表述。

### 5.3 最小不可满足核心

1. Bellman-Ford 检测到负环时，沿前驱回溯取得该环（本身就是一个不可满足集）。
2. 删除法最小化：对集合中每条约束 `c`，若去掉 `c` 后仍不可满足则永久删除。
   可行性对子集单调，因此一遍即得**子集最小**核心。
3. 复验：核心不可满足；对每个成员 `c`，`核心 \ {c}` 可行。结果写入 `certificate`。
4. 需要更多核心时：撤回已报告核心，重解，重复（每轮核心互不相交）。

复杂度：一次判定 `O(V·E)`；核心最小化至多 `|seed|` 次判定。样例规模（11 事件 /
39 约束）毫秒级完成。

### 5.4 确定性

* 所有遍历、输出排序都基于 `(host, boot_id, seq, id)` 或约束编号 `cNNNN`（按构造顺序）。
* 线性扩展的堆键固定；并发对的打破方式固定，并在 `certificate` 中计数。
* 样例生成器不用随机数；`tests/test_samples.py` 重跑生成器并断言**逐字节相同**。
* `tests/test_samples.py::test_two_runs_of_the_same_case_agree` 断言两次运行结果 JSON
  完全相等（固定种子可重放）。

---

## 6. 错误码

`diagnostics[]` 中每条都带注册码。`fatal` 码出现即 `status = "error"` 且不再继续；
其余是"记录级"问题——只影响相关记录，并在 `status` 上如实反映（`conflict` /
`partial`）。

| 码 | 级别 | 含义 |
| --- | --- | --- |
| `E_INPUT_MISSING` | fatal | cases 文件或源文件不存在 |
| `E_INPUT_IO` | fatal | 输入文件无法读取 |
| `E_INPUT_JSON` | fatal | cases（或清单）不是合法 JSON |
| `E_INPUT_SCHEMA` | fatal | cases（或清单）不符合 schema |
| `E_OUTPUT_WRITE` | fatal | 结果无法写入（退出码 3） |
| `E_PATH_OUTSIDE_ROOT` | fatal | 源路径逃出 cases 所在目录树 |
| `E_SOURCE_HASH` | fatal | 同一文件两次读取的哈希不一致（分析期间被改动） |
| `E_SOURCE_READ` | fatal | 源文件读取失败 |
| `E_INTERNAL` | fatal | 未预期异常（带限长 traceback） |
| `E_LINE_ENCODING` | 记录 | 行内非法 UTF-8 字节 |
| `E_LINE_JSON` | 记录 | 行不是合法 JSON |
| `E_LINE_SCHEMA` | 记录 | 记录不符合 schema（缺字段/类型错/未知 type/保留 id 前缀） |
| `E_TIMESTAMP` | 记录 | 时间戳格式非法 |
| `E_CALIBRATION` | 记录 | 校准字段缺失或类型错 |
| `E_BOOT_ID` | 记录 | 同一 `(host,boot_id)` 被不同校准复用 |
| `E_BOOT_MISSING` | 记录 | 事件所属 boot 没有校准记录 → 该事件排除出时间线 |
| `E_DUPLICATE` | 记录 | **内容完全一致**的重复采集，已合并（保留每次的位置） |
| `E_ID_CONFLICT` | 记录 | 同 ID 异内容：证据冲突，该 ID 排除出时间线 |
| `E_SIG_INVALID` | 记录 | 签名校验失败（记录被丢弃） |
| `E_SIG_MISSING` | 记录 | 已知该主机公钥但记录没有 `sig`（记录被丢弃） |
| `E_SIG_UNVERIFIED` | 记录 | 没有该主机公钥，签名未校验（记录保留并如实标注） |
| `E_SEAL_INVALID` | 记录 | 清单封印与主体不符 |
| `E_SEAL_UNVERIFIED` | 记录 | 清单带封印但没有密钥，未校验 |
| `E_MANIFEST_HASH_MISMATCH` | 记录 | 实读哈希/字节数与清单不符 |
| `E_MANIFEST_MISSING_ENTRY` | 记录 | 分析的源未在清单中登记 |
| `E_MANIFEST_EXTRA_ENTRY` | 记录 | 清单登记的文件未参与本次分析 |
| `E_DANGLING` | 记录 | `message_id` 只有一端（或仅被排除事件引用），不加因果约束 |
| `E_MESSAGE_PAIR` | 记录 | `message_id` 端点不唯一（多发送/多接收/自配对），不加因果约束 |
| `E_MONO_ANOMALY` | 记录 | 同一 boot 内单调计时倒退，不加经过时间约束 |
| `E_SEQ_DUP` | 记录 | 同一 boot 内 `seq` 重复，这些事件互不排序 |
| `E_REBOOT_ORDER` | 记录 | `follows` 指向的 boot 不存在或为空，声明被忽略 |
| `E_CONTRADICTION` | 记录 | 约束矛盾，已定位最小核心 |
| `E_ORDER_CYCLE` | 记录 | 严格先后关系成环（理论上不应出现；出现即内部不一致） |

---

## 7. 验收场景与样例

| 场景 | 样例 | 工具给出的结论（测试断言的具体值） |
| --- | --- | --- |
| 时钟回拨 | `samples/scenarios/clock_rollback` | `contradiction`；3 条约束的最小核心 = `{wall_lo(roll-002), wall_hi(roll-003), mono_elapsed(roll-003→roll-002)}`；撤回核心后时间线恢复为 `roll-001..004` |
| 重启 | `samples/scenarios/reboot`（及 main 的 web01 b1→b2） | `ok`；跨 boot 不比较单调计时（无 `E_MONO_ANOMALY`）；b2 首事件由消息/声明重启顺序证明在 b1 末事件之后 |
| 重复采集 | `samples/scenarios/duplicate`、main 的 `*_copy` | 内容一致的重复合并为一个节点、保留两处行号与字节区间（`E_DUPLICATE`）；同 ID 异内容成为 `conflicts` 且该 ID 排除 |
| 发送接收矛盾 | `samples/scenarios/send_recv` | `contradiction`；3 条约束核心 = `{message(s1→r1), wall_hi, wall_lo}`；只撤回 message 后 `r1` 早于 `s1` |
| 区间部分重叠 | `samples/scenarios/overlap`、main 的 `jump01-b1-001/002` vs `web01-b1-003` | `ok` 且 `concurrent`；两方向 `separation_bounds_ns` 均 > 0；拓扑展示把这对并发的打破次数单列 |
| 最小核心 | `samples/scenarios/core_minimal` | 核心 3 条 < 全系统约束数；每个成员删除后可行（`certificate` 全 true） |

---

## 8. 安全边界与设计取舍（README 承诺的范围）

1. **离线、只读**。不发起网络请求，不启动服务，不调用外部程序。源文件以 `rb` 打开，
   两次读取 + 分析后再哈希一次，`integrity.sources_unchanged` 只在三次哈希一致时为
   `true`。`tests/test_integrity.py` 用目录快照断言运行前后逐字节相同。
2. **真实性的边界**。记录级真实性 = 主机 Ed25519 签名（规范化 JSON 覆盖全部字段）。
   清单级封印 = HMAC-SHA256，密钥**不随项目分发**：没有密钥时只报"未校验"。样例中的
   示例密钥已明确标注不可用于真实场景。没有真实性保证的宿主仍会被分析，但其
   `signature` 标为 `unverified`，绝不显示为 `valid`。
3. **不伪造确定性**。并发就写并发；矛盾就写矛盾并给核心；系统不可满足时不输出
   可行窗口与拓扑序列。线性扩展明确标注是展示手段。
4. **去重口径窄**。只有"同 ID + 规范化内容完全一致"才合并。位置不同的同一事实也算
   冲突，因为取证上无法证明两者等价。
5. **不写入输入目录**。结果文件用临时文件 + `os.replace` 原子写入；临时目录默认在
   `.runtime-tmp/`（已在 `.gitignore`）。
6. **不引入外部依赖**。`cryptography` 在题面允许范围内，但环境中未安装；因此内置
   了符合 RFC 8032 的 Ed25519 实现，并用 RFC 8032 §7.1 官方向量做测试。如果要改用
   `cryptography`，只需替换 `solution/crypto/ed25519.py` 的 `sign`/`verify`，其余
   代码与测试不变。

### 为什么不需要 cryptography

| 需求 | 实现 | 验证 |
| --- | --- | --- |
| Ed25519 签名/验签 | `solution/crypto/ed25519.py`（纯 Python，RFC 8032） | `tests/test_ed25519.py` 用 3 组 RFC 官方向量断言公钥、签名逐字节相等 |
| SHA-256 内容摘要 | 标准库 `hashlib` | 与 `hashlib` 直接比对 |
| 清单封印 | 标准库 `hmac` + `hashlib` | 往返、错密钥、改主体三类断言 |

纯 Python Ed25519 的验签速度约为毫秒级/条，样例规模（十一条记录）完全够用；它**不是**
侧信道加固的实现，这一点在模块 docstring 里明确写出。

---

## 9. 测试

```
python -m unittest discover -s tests -v
```

169 个测试，全部断言具体结果而非"没有抛异常"：

| 文件 | 覆盖 |
| --- | --- |
| `test_ed25519.py` | RFC 8032 向量、篡改/错密钥/畸形签名拒绝、规范化 JSON、封印 |
| `test_time_and_sources.py` | RFC 3339 解析/格式化、非法时间戳、字节切片覆盖每个字节、CRLF、多字节 UTF-8 |
| `test_constraints.py` | 差分约束语义、严格先后、并发、负环、核心最小性（逐条删除复验）、三求解器随机一致性（固定种子 120+ 组）、暴力枚举对照 |
| `test_scenarios.py` | 五个验收场景的端到端断言：状态、核心成员、可行窗口、并发对称性、拓扑证书 |
| `test_bruteforce.py` | 小系统上与穷举逐对对照；并发必须有 `t_a == t_b` 见证；窗口上下界等于枚举结果；管线导出的约束再次穷举复核 |
| `test_integrity.py` | 哈希与独立计算一致、前后一致、每次采集的字节区间可复现、清单/封印四类情形、运行前后目录快照不变 |
| `test_malformed_and_structure.py` | 非法 JSON/UTF-8/BOM/schema/时间戳、签名四态、缺 boot、校准冲突、单调倒退、seq 重复、消息配对错误、保留 id；跨样例的计数自洽 |
| `test_cli.py` | 子进程跑 `python -m solution`：退出码 0/1/2/3、输出目录创建、路径越界、错误码均已在注册表登记、`--check`、`--quiet`、`--help` |
| `test_status.py` | 状态汇总：干净即 `ok`；字节一致的重复不降级；未校验/签名失败/悬空消息降为 `partial`；同 ID 异内容为 `conflict`；矛盾优先于一切 |
| `test_drift.py` | 漂移预算：不足即矛盾（核心含 `mono_elapsed`）、足够即可行、精确阈值 125 ppm 复验、boot 级覆盖、负值被拒 |
| `test_graph.py` | 图的节点/边与约束一一对应、端点合法、与拓扑展示一致、DOT 确定性且可简单解析、矛盾时不出 precedence/并发边 |
| `test_invariants.py` | 全部样例的全局不变量：状态取值、errors 与诊断一致、反称性、并发对称、并发对绝无 -1 ns 界、拓扑序列尊重所有已证先后、简约边无中间节点、核心在三个求解器下均最小、完整性哈希处处一致 |
| `test_samples.py` | 样例生成器重跑**逐字节相同**、两次运行结果完全相同、每个样例的取证结论（含 main 的 5 个错误码、8 条合并、1 个 ID 冲突、4 对并发、拓扑证书）；另外**不经过采集器**、只用公钥与规范化 JSON 独立复核样例中 18 条签名，以及篡改记录确实验签失败 |

固定种子：所有签名用固定种子（`tests/_support.py` 的 `SEED_H1/H2/H3`）；随机化测试
使用显式 `random.Random(<常数>)`。

---

## 10. 已知边界

* 只处理题面要求的三类证据（墙钟校准、boot 内序号/单调计时、消息因果）与可选的
  `follows` 声明；不推断未声明的重启顺序，也不从墙钟猜重启先后。
* 分辨率固定 1 ns，"严格早于"即"至少早 1 ns"。输出中显式声明
  `case.resolution_ns = 1`。
* 采集清单的封印依赖环境变量密钥；未设置时只报告"未校验"。
* 单机纯内存实现：所有源文件读入内存（取证场景文件通常为 MB 级）。事件数超过 256
  时省略逐对明细，但偏序关系本身完整。
* 纯 Python Ed25519 未做侧信道防护；如需高吞吐或加固实现，用 `cryptography` 替换
  `solution/crypto/ed25519.py` 即可。
