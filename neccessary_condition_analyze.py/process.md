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