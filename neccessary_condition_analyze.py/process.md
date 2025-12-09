## 流程总览
两阶段流水线：先清洗与诊断，再聚类与蒸馏。

```
           原始数据
               │  all_cves_combined.json
               ▼
┌────────────────────────┐
│  01_analyze_vulnerabilities.py │
│  单样本清洗 + AI 诊断          │
└────────────────────────┘
               │  silicon_analysis_results.json
               ▼
┌────────────────────────┐
│   02_synthesize_rules.py      │
│   聚类筛选 + 规则蒸馏          │
└────────────────────────┘
               │  silicon_cwe_rules.json
               ▼
         必要条件公式
```

## 第一阶段：单样本清洗与诊断（Script 1）
**输入**：`tools/output/vulnerability_code/all_cves_combined.json`（120+ CVE，多片段，含测试/无关代码）

1) 物理去噪  
   - 过滤文件：关键词 `test/mock/example` 剔除测试/示例代码，保留业务主干  
   - 片段优选：在剩余文件中选行数最长的片段，保留上下文

2) AI 深度审计  
   - Prompt：`CVE ID + NVD Description + Code Snippet`  
   - CWE 归类：推断漏洞所属 CWE（如 `CWE-22`）  
   - 缺陷定位：提取缺失的逻辑检查 (`Missing_Condition`)  
   - 质量打分：`is_classic` 与 `confidence (1-10)`

3) 结构化输出  
   - 产物：`silicon_analysis_results.json`（带语义标签和质量分数）

## 第二阶段：聚类与规则蒸馏（Script 2）
**输入**：`silicon_analysis_results.json`

1) 逻辑聚类  
   - 按 `Inferred_CWE` 分桶（如将所有 `CWE-22` 样本归组）

2) 质量过滤  
   - 丢弃失败样本或 `confidence ≤ 7` 且非经典的记录  
   - 组内按置信度排序，取 Top 15 作为证据链

3) 抽象蒸馏  
   - Prompt：拼接该组 Top 15 的 `Missing_Condition`，要求忽略代码细节、保留逻辑共性  
   - 规则生成：输出该 CWE 的必要条件公式（如 `IF 输入可控 AND 未归一化 -> 漏洞`）

4) 输出  
   - 产物：`silicon_cwe_rules.json`（包含定义、核心公式、防御原则）

 
Q: 这些样本能否让 LLMs 自动总结出必要条件？

- A: 能，但不能“直接喂”。 如果直接把 100 个代码扔给 LLM 让它总结，它会晕头转向，因为样本里混杂了测试代码、复杂业务逻辑和配置错误。

- 策略：采用 Map-Reduce（映射-归约） 架构。先让 LLM 单独看每个样本（Map），提取出核心逻辑原子；再将同类别的逻辑原子聚合，让 LLM 归纳出通用公式（Reduce）。

Q: 如何处理不那么经典的“非典型样本”？

- A: 采用“质量加权”与“择优录取”机制。

- 策略：我们在第一阶段引入了 元认知（Meta-Cognition）。让 LLM 在分析漏洞的同时，自我评估这个样本的质量（Quality_Assessment）。在第二阶段归纳时，程序会自动丢弃低分样本，只用高置信度的“经典样本”作为归纳的证据。