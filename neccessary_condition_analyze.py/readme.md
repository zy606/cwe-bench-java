image.png
本项目实现了一个基于 Gemini 2.5 Flash 的自动化流水线，旨在从 Java 漏洞数据集（CWE-Bench-Java）中自动提取漏洞发生的**“必要条件公式” (Necessary Condition Formula)**。

通过“分而治之”的策略，项目首先对海量原始漏洞代码进行清洗和质量打分，然后针对高质量的“经典样本”进行归纳，最终生成抽象的漏洞成因逻辑规则。
🚀 项目架构
本项目包含两个核心脚本，构成了一个漏斗式的数据处理流程：

⛏️ 淘金者 (01_analyze.py) - 单样本分析与清洗

输入: 原始 CVE 数据集 (all_cves_combined.json)。

功能:

去噪: 自动剔除测试代码 (test, mock, example) 和无效片段。

分析: 识别漏洞触发点 (Trigger Point) 和缺失的检查 (Missing Condition)。

打分: 核心功能。对样本进行 质量评估 (Quality Assessment)，标记其是否为“经典样本” (is_classic) 并给出置信度打分。

输出: 带有 LLM 分析元数据的中间结果 (gemini_analysis_results.json)。

⚗️ 冶炼师 (02_synthesize.py) - 择优归纳与规则生成

输入: 上一步的分析结果。

功能:

过滤: 仅保留被标记为 is_classic=True 且 confidence 高的优质样本。

聚合: 按 CWE ID 将样本分组。

蒸馏: 让 LLM 根据一组高质量样本，总结出该漏洞类型的通用逻辑公式。

输出: 最终的 CWE 规则集 (cwe_synthesis_rules.json)。

🛠️ 环境依赖
Python: 3.8+

Libraries:

Bash

pip install google-generativeai tqdm
Network: 需要能够访问 Google API 的网络环境（已配置本地代理端口 7897）。

📂 文件结构
Plaintext

D:\CVE\cwe-bench-java1\
├── neccessary_condition_analyze.py\
│   ├── 01_analyze.py               # [脚本1] 单样本分析主程序
│   ├── 02_synthesize.py            # [脚本2] 规则归纳主程序
│   ├── gemini_analysis_results.json # [中间产物] 包含质量打分的详细分析
│   └── cwe_synthesis_rules.json     # [最终产物] 提取出的漏洞必要条件公式
└── tools\output\vulnerability_code\
    └── all_cves_combined.json      # [原始数据] 漏洞代码源文件
⚙️ 配置说明
在运行脚本前，请确保脚本文件头部的 配置区域 与你的环境一致：

Python

# 代理设置 (根据你的 VPN/代理软件端口修改)
os.environ["http_proxy"] = "http://127.0.0.1:7897"
os.environ["https_proxy"] = "http://127.0.0.1:7897"

# Google AI Studio Key
API_KEY = "Your_API_Key_Here"

# 模型选择 (推荐 Flash 以兼顾速度和效果)
MODEL_NAME = "gemini-2.5-flash"
🏃‍♂️ 运行指南
第一步：启动分析流水线
运行脚本 1，对原始数据进行清洗和打分。

Bash

python 01_analyze.py
说明: 脚本会显示进度条。由于内置了抗 Rate Limit 机制，如果遇到 429 错误，脚本会自动休眠 65 秒后重试。

耗时: 取决于 BATCH_SIZE。处理 10 个样本约需 30-60 秒。

第二步：生成漏洞规则
当第一步完成后，运行脚本 2 进行知识蒸馏。

Bash

python 02_synthesize.py
说明: 脚本会自动读取中间结果，按 CWE 分组，并过滤掉劣质样本。

结果: 控制台将打印生成的规则预览，完整 JSON 保存至输出目录。

📝 输出示例
1. 中间分析结果 (Script 1 Output)
LLM 不仅识别了漏洞，还给出了样本质量评价。

JSON

{
  "cve_id": "CVE-2018-9159",
  "analysis": {
    "Inferred_CWE": "CWE-22",
    "Missing_Condition": "Input path is used directly in getResource without validation.",
    "Quality_Assessment": {
      "is_classic": true,        // <--- 关键标签
      "confidence": 9
    }
  }
}
2. 最终规则公式 (Script 2 Output)
这是高度抽象后的逻辑公式，不依赖具体代码实现。

JSON

{
  "cwe_id": "CWE-22",
  "definition": "Improper Limitation of a Pathname to a Restricted Directory",
  "necessary_condition_formula": "IF (User Input controls File Path) AND (Input contains directory separators '../') AND (No Canonicalization Check) -> Vulnerability",
  "preventative_principle": "Normalize the path and verify it starts with the expected base directory."
}
⚠️ 注意事项
Rate Limits: Google Gemini 免费层级有限制。脚本已内置自动休眠策略，请勿强行移除 time.sleep。

数据路径: 脚本中使用了硬编码的绝对路径。如果在不同机器上运行，请务必修改 INPUT_FILE_PATH。

JSON 容错: clean_and_parse_json 函数会自动修复 LLM 输出中常见的 JSON 格式错误（如反斜杠问题），无需人工干预。