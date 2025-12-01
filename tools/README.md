# Tools 使用手册

欢迎使用 CWE-Bench-Java 漏洞数据挖掘工具集！

## 📚 文档导航

- **[完整使用手册](docs/README.md)** - 功能说明、详细使用指南、脚本使用方式
- **[配置指南](docs/CONFIG.md)** - 详细配置说明、故障排除
- **[JSON 结构](docs/JSON_HIERARCHY.txt)** - 输出数据结构详细说明

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

## 📋 核心脚本

| 脚本 | 功能 | 输出目录 |
|------|------|----------|
| **Vulnerability_Code_Extractor.py** | 漏洞代码提取 + NVD 元数据（推荐） | `output/vulnerability_code/` |
| **VulnCodeMiner.py** | 漏洞代码提取 + NVD 元数据（旧版本） | `output/vulnerability_code_legacy/` |
| **NVD_Fetcher.py** | 仅 NVD 数据抓取 | `output/nvd_data/` |

## ⚙️ 配置方式

支持三种配置方式（优先级从高到低）：
1. **环境变量**：`CWE_BENCH_JAVA_ROOT`, `NVD_API_KEY`
2. **配置文件**：`tools/config/config.json`
3. **自动检测**：从 tools 目录向上查找

**详细配置说明**：[docs/CONFIG.md](docs/CONFIG.md)

## 📖 查看完整文档

**查看完整使用手册**：[docs/README.md](docs/README.md)

包含：
- 各脚本详细使用方式
- 交互模式和批量模式说明
- 输出文件说明
- 脚本对比和使用建议

## 🤝 致谢

本工具基于 [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) 数据集构建。

**License**: MIT
