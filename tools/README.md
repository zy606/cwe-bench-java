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
```

### 2. 准备数据源

本项目依赖 `cwe-bench-java` 的原始 CSV 数据。请确保你的目录结构如下：

```text
VulnCodeMiner/
├── data/
│   ├── project_info.csv   # 包含 CVE ID, GitHub URL, Commit ID
│   └── fix_info.csv       # 包含 文件路径, 函数名, 签名
├── tools/
│   └── Final_Vuln_Miner_v5_1.py  # 本工具脚本
└── README.md
```

### 3. 配置脚本

打开 `Final_Vuln_Miner_v5_1.py`，在底部的 `__main__` 区域修改配置：

```python
# 设置你的本地仓库路径
REPO_ROOT = r"D:\path\to\your\cwe-bench-java"

# 设置 NVD API Key (推荐申请一个，否则速度受限)
# 申请地址: [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
MY_API_KEY = "your-nvd-api-key-here"
```

### 4. 运行

```bash
python Final_Vuln_Miner_v5_1.py
```

程序启动后，你可以选择：
* `[1]` **单个查询模式**：输入 CVE 号进行调试，结果生成单独的 JSON 文件。
* `[2]` **批量全量处理**：自动处理所有数据，结果合并存入 `final_dataset_v5/all_cves_combined.json`。

---

## 📄 输出数据结构

工具生成的 `all_cves_combined.json` 包含丰富的结构化信息，非常适合用于大模型训练或安全分析。

**示例结构：**

```json
[
  {
    "cve_id": "CVE-2020-5405",
    "project_slug": "spring-cloud-config_CVE-2020-5405...",
    "buggy_commit_id": "24e7292...",
    "github_url": "[https://github.com/spring-cloud/spring-cloud-config](https://github.com/spring-cloud/spring-cloud-config)",
    
    "nvd_metadata": {
      "description": "Spring Cloud Config versions 2.2.x prior to 2.2.2...",
      "cvss_v3_score": 6.5,
      "severity": "MEDIUM",
      "published_date": "2020-03-05T19:15:11.700"
    },

    "code_snippets": [
      {
        "file_path": "src/main/java/.../ResourceController.java",
        "class_name": "ResourceController",
        "method_name": "retrieve",
        "signature": "String retrieve(ServletWebRequest,String,...)",
        
        "code": "public void retrieve(...) { \n    // 完整的漏洞触发代码... \n}",
        "is_missing_in_buggy_version": false,
        "status": "FOUND"
      },
      {
        "file_path": "src/main/java/.../ResourceController.java",
        "method_name": "checkNotModified",
        "code": "",
        "is_missing_in_buggy_version": true, 
        "status": "METHOD_MISSING" 
        // 标记：该函数在漏洞版本中不存在（属于修复新增）
      }
    ]
  }
]
```

---

## 📝 常见问题 (FAQ)

**Q: 为什么有些 code 字段是空的？**

A: 请检查 `is_missing_in_buggy_version` 字段。如果是 `true`，说明这个函数是修复补丁中**新增**的（例如新增的安全检查函数）。在漏洞版本（Buggy Version）中它本身就不存在，这是正常的。

**Q: 为什么运行速度比较慢？**

A: 为了防止被 NVD 或 GitHub 封禁 IP，脚本内置了速率限制（Rate Limiting）。
* GitHub: 每次请求间隔 0.3s
* NVD: 有 API Key 间隔 1.0s，无 Key 间隔 6.0s
* 如果处理 100+ 个 CVE，可能需要几分钟时间。

---

## 🤝 致谢

本工具基于 [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) 数据集构建。感谢原作者整理的基础数据。