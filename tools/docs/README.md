# Integrated Vulnerability Miner for CWE-Bench-Java

专为 [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) 数据集设计的漏洞数据挖掘工具。整合了 **NVD (National Vulnerability Database)** 的官方元数据和 **GitHub** 的历史代码快照，自动爬取 CVE 详情并提取存在漏洞的代码片段。

## 📚 文档导航

- **[配置指南](CONFIG.md)** - 详细配置说明、故障排除
- **[JSON 结构](JSON_HIERARCHY.txt)** - 输出数据结构详细说明

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install pandas requests
```

### 2. 配置环境

```powershell
# 复制配置文件
copy tools\config\config.json.example tools\config\config.json

# 编辑 tools\config\config.json，设置你的路径
```

### 3. 运行脚本

```powershell
# 运行漏洞代码提取器（推荐）
python tools\Vulnerability_Code_Extractor.py

# 或运行 NVD 数据抓取器
python tools\NVD_Fetcher.py
```

## 📁 目录结构

```
tools/
├── 核心脚本/
│   ├── Vulnerability_Code_Extractor.py  # 漏洞代码提取器（推荐）
│   ├── VulnCodeMiner.py                  # 漏洞挖掘器（旧版本）
│   └── NVD_Fetcher.py                    # NVD 数据抓取器
│
├── 配置系统/
│   ├── config.py                         # 统一配置模块
│   └── config/                           # 配置目录
│       ├── config.json.example           # 配置示例（可提交到 Git）
│       ├── config.json                   # 个人配置（不提交到 Git）
│       └── test_config.py                # 配置测试脚本
│
├── 文档/
│   └── docs/                             # 文档目录
│       ├── README.md                     # 本文件（完整使用手册）
│       ├── CONFIG.md                     # 详细配置指南
│       └── JSON_HIERARCHY.txt            # JSON 数据结构说明
│
├── output/                               # 输出目录（所有脚本的输出）
│   ├── vulnerability_code/               # 漏洞代码提取结果（推荐脚本）
│   ├── vulnerability_code_legacy/        # 漏洞代码提取结果（旧版本）
│   ├── nvd_data/                         # NVD 数据抓取结果
│   └── logs/                             # 日志文件目录
│
└── .gitignore                            # Git 忽略规则
```

## 🚀 主要功能

1. **NVD API 深度集成**
   - 自动获取漏洞描述、CVSS V3 评分、严重等级和发布日期
   - 支持 API Key 加速请求，内置自动重试机制

2. **智能代码提取算法**
   - 解决代码版本回退导致 CSV 行号与实际代码不匹配的问题
   - 结合方法名、方法签名关键词和提示行号进行多维度加权评分
   - 使用括号平衡算法确保提取完整的函数体

3. **灵活的运行模式**
   - **单查模式**：输入单个 CVE ID 查看提取结果
   - **批量模式**：自动扫描所有 CVE，支持断点续传

4. **数据清洗与结构化**
   - 将项目信息、修复定位信息、漏洞元数据整合为统一的 JSON 格式

## 🛠️ 环境要求

- Python 3.8+
- 依赖库：`pandas`, `requests`

安装依赖：
```bash
pip install pandas requests
```

## ⚙️ 快速配置

### 方式1：配置文件（推荐）

1. 复制示例配置文件：
   ```powershell
   copy tools\config\config.json.example tools\config\config.json
   ```

2. 编辑 `tools/config/config.json`，设置你的路径：
   ```json
   {
     "repo_root": "D:/CVE/cwe-bench-java1",
     "nvd_api_key": "your-api-key-here"
   }
   ```

### 方式2：环境变量

```powershell
$env:CWE_BENCH_JAVA_ROOT = "D:\CVE\cwe-bench-java1"
$env:NVD_API_KEY = "your-api-key"
```

### 方式3：自动检测

如果脚本在项目根目录下运行，会自动检测路径（无需配置）。

**详细配置说明请参考：[配置指南](CONFIG.md)**

## 🖥️ 使用指南

### 1. Vulnerability_Code_Extractor.py（推荐）

漏洞代码提取器，功能最完整，支持智能代码提取算法。

#### 运行方式

```powershell
# 从项目根目录运行
python tools\Vulnerability_Code_Extractor.py
```

#### 交互模式

运行后会显示菜单：
```
1.单查 / 2.批量 / q.退出
```

- **选项 1 - 单查模式**：
  - 输入单个 CVE ID（如：`CVE-2016-10726`）
  - 输出：`output/vulnerability_code/debug_CVE-xxxx-xxxx.json`
  - 用途：快速验证某个特定的 CVE 是否能被正确抓取和解析

- **选项 2 - 批量模式**：
  - 自动扫描 `data/project_info.csv` 中的所有 CVE
  - 输出：`output/vulnerability_code/all_cves_combined.json`
  - 支持断点续传（自动跳过已处理的 CVE）
  - 每处理 5 个 CVE 自动保存一次，防止意外中断

- **选项 q - 退出**

#### 批量模式（非交互式）

```powershell
# Windows PowerShell
echo "2`ny" | python tools\Vulnerability_Code_Extractor.py

# 或使用管道
"2", "y" | python tools\Vulnerability_Code_Extractor.py
```

#### 输出说明

- **单查模式输出**：`output/vulnerability_code/debug_CVE-xxxx-xxxx.json`
- **批量模式输出**：`output/vulnerability_code/all_cves_combined.json`
- 包含完整的 CVE 信息、NVD 元数据和提取的代码片段

---

### 2. VulnCodeMiner.py

漏洞挖掘器（旧版本），保留用于兼容性。

#### 运行方式

```powershell
python tools\VulnCodeMiner.py
```

#### 使用方式

与 `Vulnerability_Code_Extractor.py` 类似，但功能较旧：

- **选项 1 - 单查模式**：输入单个 CVE ID
- **选项 2 - 批量模式**：批量处理所有 CVE

#### 输出说明

- **单查模式输出**：`output/vulnerability_code_legacy/debug_CVE-xxxx-xxxx.json`
- **批量模式输出**：`output/vulnerability_code_legacy/all_cves_combined.json`

---

### 3. NVD_Fetcher.py

独立的 NVD 数据抓取工具，用于获取 CVE 的官方元数据。

#### 运行方式

```powershell
python tools\NVD_Fetcher.py
```

#### 交互菜单

运行后会显示菜单：
```
1. [单次] 输入 CVE 号查询
2. [批量] 处理 cwe-bench-java 数据集
3. [汇总] 仅运行合并数据 (生成CSV)
q. 退出程序
```

#### 使用说明

- **选项 1 - 单次查询**：
  - 输入 CVE 号（如：`CVE-2016-10726`）
  - 输出：`output/nvd_data/CVE-xxxx-xxxx.json`
  - 用途：单独查询某个 CVE 的 NVD 信息

- **选项 2 - 批量处理**：
  - 自动读取 `data/project_info.csv` 中的所有 CVE
  - 批量下载 NVD 数据
  - 输出：`output/nvd_data/CVE-*.json`（每个 CVE 一个文件）
  - 支持断点续传（跳过已存在的文件）
  - 每处理 10 个自动汇总一次

- **选项 3 - 汇总数据**：
  - 扫描 `output/nvd_data/` 目录下所有 JSON 文件
  - 生成汇总文件：
    - `output/nvd_data/all_cves_combined.json` - 完整 JSON 数据
    - `output/nvd_data/all_cves_combined.csv` - 扁平化 CSV 表格（Excel 可打开）

- **选项 q - 退出**

#### 输出说明

- **单次查询输出**：`output/nvd_data/CVE-xxxx-xxxx.json`
- **批量处理输出**：`output/nvd_data/CVE-*.json`（多个文件）
- **汇总输出**：
  - `output/nvd_data/all_cves_combined.json`
  - `output/nvd_data/all_cves_combined.csv`

---

### 4. 配置相关脚本

#### config.py - 配置测试

快速测试配置是否正确：

```powershell
python tools\config.py
```

**输出示例**：
```
=== 配置测试 ===
✅ 项目根路径: D:\CVE\cwe-bench-java1
✅ data/project_info.csv 存在: True
✅ NVD API Key: fb382a79-0...
```

#### test_config.py - 完整配置测试

测试配置并验证脚本导入：

```powershell
python tools\config\test_config.py
```

**输出示例**：
```
=== 配置测试 ===
✅ 项目根路径: D:\CVE\cwe-bench-java1
✅ CSV 文件存在: True
✅ NVD API Key: fb382a79-0...

=== 测试脚本导入 ===
✅ Vulnerability_Code_Extractor 导入成功
✅ 初始化成功，项目数: 120
```

---

## 📋 核心脚本对比

| 脚本 | 推荐度 | 主要功能 | 输出目录 | 特点 |
|------|--------|----------|----------|------|
| **Vulnerability_Code_Extractor.py** | ⭐⭐⭐⭐⭐ | 漏洞代码提取 + NVD 元数据 | `output/vulnerability_code/` | 功能最完整，推荐使用 |
| **VulnCodeMiner.py** | ⭐⭐⭐ | 漏洞代码提取 + NVD 元数据 | `output/vulnerability_code_legacy/` | 旧版本，保留兼容 |
| **NVD_Fetcher.py** | ⭐⭐⭐⭐ | 仅 NVD 数据抓取 | `output/nvd_data/` | 独立的 NVD 工具 |

## 💡 使用建议

1. **首次使用**：先运行 `python tools\config.py` 验证配置
2. **单 CVE 测试**：使用单查模式验证某个 CVE 是否能正确提取
3. **批量处理**：确认配置正确后，使用批量模式处理所有 CVE
4. **仅需 NVD 数据**：使用 `NVD_Fetcher.py` 单独获取 NVD 元数据
5. **断点续传**：所有批量处理都支持断点续传，可随时中断和恢复

## 📂 输出数据结构

生成的 JSON 文件结构：

```json
[
  {
    "cve_id": "CVE-2016-10726",
    "project_slug": "DSpace__DSpace_CVE-2016-10726_4.4",
    "buggy_commit_id": "ca4c86b1baa4e0b07975b1da86a34a6e7170b3b7",
    "github_url": "https://github.com/DSpace/DSpace",
    "nvd_metadata": {
      "description": "...",
      "published_date": "2018-07-10T11:29:00.223",
      "cvss_v3_score": null,
      "severity": null
    },
    "code_snippets": [
      {
        "file_path": "src/.../X.java",
        "class_name": "X",
        "method_name": "method",
        "signature": "Type method(Type)",
        "lines_hint_csv": [10, 20],
        "code": "public Type method(Type t) {\n  ...\n}",
        "status": "FOUND",
        "lines_extracted": [12, 22],
        "is_missing_in_buggy_version": false
      }
    ]
  }
]
```

**详细结构说明请参考：[JSON_HIERARCHY.txt](JSON_HIERARCHY.txt)**

## 🔍 状态码说明

- `FOUND`: 成功定位并提取代码
- `FILE_MISSING`: 无法从 GitHub Raw 链接下载文件
- `METHOD_MISSING`: 文件存在，但找不到指定的方法名
- `EMPTY_BODY`: 方法被找到，但无法提取内容

## 📝 文件说明

### 核心脚本

- **Vulnerability_Code_Extractor.py** - 推荐使用，功能最完整
- **VulnCodeMiner.py** - 旧版本，保留兼容
- **NVD_Fetcher.py** - 独立的 NVD 数据抓取工具

### 配置系统

- **config.py** - 统一配置模块（位于 tools 根目录，方便导入）
- **config/config.json** - 个人配置文件（不提交到 Git）
- **config/config.json.example** - 配置示例（可提交到 Git）
- **config/test_config.py** - 配置测试脚本

### 输出目录

所有脚本的输出统一保存在 `output/` 目录下：

- `output/vulnerability_code/` - Vulnerability_Code_Extractor.py 的输出
  - `all_cves_combined.json` - 批量处理结果
  - `debug_CVE-xxxx-xxxx.json` - 单查模式结果
  
- `output/vulnerability_code_legacy/` - VulnCodeMiner.py 的输出（旧版本）
  - `all_cves_combined.json` - 批量处理结果
  - `debug_CVE-xxxx-xxxx.json` - 单查模式结果
  
- `output/nvd_data/` - NVD_Fetcher.py 的输出
  - `CVE-xxxx-xxxx.json` - 单个 CVE 的 NVD 数据
  - `all_cves_combined.json` - 汇总 JSON 数据
  - `all_cves_combined.csv` - 汇总 CSV 数据

### 日志系统

所有脚本的日志文件统一保存在 `output/logs/` 目录下：

- `output/logs/vulnerability_code_extractor.log` - Vulnerability_Code_Extractor.py 的运行日志
- `output/logs/vuln_code_miner.log` - VulnCodeMiner.py 的运行日志
- `output/logs/nvd_fetcher.log` - NVD_Fetcher.py 的运行日志

日志文件记录：
- CSV 数据加载情况
- 每个 CVE 的处理进度
- 网络请求错误或文件解析异常
- 配置加载情况

**注意**：日志文件会持续追加，建议定期清理或归档。

## 🤝 致谢

本工具基于 [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) 数据集构建。

**License**: MIT
