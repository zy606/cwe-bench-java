# VulnCodeMiner 🛡️

**VulnCodeMiner** 是一个高级的漏洞数据构建工具，专为 Java 漏洞研究设计。

它能够将 **NVD (National Vulnerability Database)** 的自然语言描述与 **GitHub** 上的真实漏洞代码片段（Buggy Code）进行精准对齐和融合。针对 `cwe-bench-java` 数据集进行了深度优化，解决了行号错位、函数截断和新增函数识别等核心痛点。

---

## ✨ 核心特性

1.  **🔍 动态函数定位 (Dynamic Search)**
    * 不盲目依赖数据集提供的 CSV 行号（这些行号往往对应修复后的版本）。
    * 使用函数名（Method Name）在 Buggy 版本文件中进行**全文动态搜索**，确保精准定位漏洞触发点。

2.  **🧠 智能上下文回溯 (Smart Context Restoration)**
    * **向上回溯**：自动向上寻找真正的函数定义头（Signature），解决数据集只标记函数内部逻辑导致的“无头代码”问题。
    * **向下补全**：利用大括号平衡算法（Bracket Balancing），自动识别函数结束位置，提取完整的函数体。

3.  **🚫 缺失函数识别 (Missing Method Detection)**
    * 自动识别修复补丁中**新增**的函数（如安全检查函数 `checkNotModified`）。
    * 在生成的 JSON 中通过 `is_missing_in_buggy_version: true` 显式标记，区分“原有漏洞代码”与“缺失的防御代码”。

4.  **📊 多源数据融合**
    * **NVD 集成**：自动爬取 CVE 描述、CVSS 评分、发布时间。
    * **GitHub 集成**：自动下载指定 Commit 的 Raw 代码。
    * **数据清洗**：自动处理 `NaN` 空值，确保 JSON 格式标准。

5.  **💾 单文件存储与断点续传**
    * 支持批量处理，所有结果实时追加到唯一的 `all_cves_combined.json` 文件中。
    * 程序崩溃或中断后，再次运行会自动跳过已处理的 CVE，无需从头开始。

---

## 🛠️ 快速开始

### 1. 环境准备
确保你的环境安装了 Python 3.x 以及以下依赖库：

```bash
pip install pandas requests