# 配置指南

## 概述

所有脚本使用统一的配置系统，支持多种方式设置项目根路径，便于多人协作。

## 配置方式（优先级从高到低）

### 方式1：环境变量（推荐用于 CI/CD）

**Windows PowerShell:**
```powershell
$env:CWE_BENCH_JAVA_ROOT = "D:\CVE\cwe-bench-java1"
$env:NVD_API_KEY = "your-api-key"
```

**Windows CMD:**
```cmd
set CWE_BENCH_JAVA_ROOT=D:\CVE\cwe-bench-java1
set NVD_API_KEY=your-api-key
```

**Linux/Mac:**
```bash
export CWE_BENCH_JAVA_ROOT="/path/to/cwe-bench-java1"
export NVD_API_KEY="your-api-key"
```

**永久设置（Windows）:**
1. 右键"此电脑" → 属性 → 高级系统设置 → 环境变量
2. 新建系统变量：`CWE_BENCH_JAVA_ROOT` = `D:\CVE\cwe-bench-java1`
3. 新建系统变量：`NVD_API_KEY` = `your-api-key`（可选）

### 方式2：配置文件（推荐用于本地开发）

1. 复制示例配置文件：
   ```powershell
   copy tools\config\config.json.example tools\config\config.json
   ```

2. 编辑 `tools/config/config.json`：
   ```json
   {
     "repo_root": "D:/CVE/cwe-bench-java1",
     "nvd_api_key": "your-api-key-here"
   }
   ```

**注意：** `config/config.json` 已在 `.gitignore` 中，不会被提交到 Git。

### 方式3：自动检测（无需配置）

如果以上方式都未配置，脚本会自动从 `tools` 目录向上查找包含 `data/project_info.csv` 的目录。

## NVD API Key 配置（可选）

NVD API Key 用于加快 NVD API 请求速度：
- 有 Key：延迟 1 秒/请求
- 无 Key：延迟 6 秒/请求

### 获取 API Key

访问：https://nvd.nist.gov/developers/request-an-api-key

### 配置方式

1. **环境变量**：设置 `NVD_API_KEY`
2. **配置文件**：在 `config.json` 中设置 `nvd_api_key`

## 测试配置

```powershell
# 快速测试
python tools/config.py

# 完整测试（包括脚本导入）
python tools/test_config.py
```

## 使用示例

### 示例1：使用配置文件

```powershell
# 1. 创建配置文件
copy tools\config.json.example tools\config.json

# 2. 编辑 config.json，设置你的路径

# 3. 运行脚本
python tools\Vulnerability_Code_Extractor.py
```

### 示例2：使用环境变量

```powershell
# 设置环境变量
$env:CWE_BENCH_JAVA_ROOT = "D:\CVE\cwe-bench-java1"
$env:NVD_API_KEY = "your-api-key"

# 运行脚本
python tools\Vulnerability_Code_Extractor.py
```

### 示例3：自动检测

```powershell
# 在项目根目录下运行，自动检测
cd D:\CVE\cwe-bench-java1
python tools\Vulnerability_Code_Extractor.py
```

## 路径结构

```
项目根目录 (repo_root)
├── data/
│   ├── project_info.csv
│   └── fix_info.csv
├── tools/
│   ├── config.py          # 配置模块
│   ├── config.json        # 个人配置文件（不提交到 Git）
│   ├── config.json.example # 配置示例（提交到 Git）
│   └── *.py               # 脚本文件
└── ...
```

## 故障排除

### 问题1：路径不存在

**错误信息：**
```
❌ 路径不存在或未配置: None
```

**解决方法：**
1. 检查环境变量是否设置正确
2. 检查 `config.json` 中的路径是否正确
3. 运行 `python tools/config.py` 测试配置

### 问题2：CSV 文件不存在

**错误信息：**
```
❌ CSV 文件不存在: D:\...\data\project_info.csv
```

**解决方法：**
1. 确认项目根路径正确
2. 确认 `data/project_info.csv` 文件存在
3. 检查路径中的斜杠方向（Windows 支持 `/` 和 `\`）

### 问题3：配置模块导入失败

**错误信息：**
```
ImportError: No module named 'config'
```

**解决方法：**
1. 确保在 `tools` 目录下运行脚本
2. 或使用 `python -m tools.Vulnerability_Code_Extractor` 运行

## 常见问题

**Q: 配置文件在哪里？**  
A: 在 `tools/config` 目录下。如果不存在，运行 `copy tools\config\config.json.example tools\config\config.json`

**Q: 路径应该怎么写？**  
A: 支持两种格式：`D:\CVE\cwe-bench-java1` 或 `D:/CVE/cwe-bench-java1`（推荐使用 `/`）

**Q: 配置优先级是什么？**  
A: 环境变量 > 配置文件 > 自动检测

**Q: 多人协作时怎么办？**  
A: 每个人创建自己的 `config.json` 文件，这个文件已经在 `.gitignore` 中，不会被提交到 Git。

## 相关文件

- `tools/config.py` - 统一配置模块
- `tools/config/config.json.example` - 配置示例文件
- `tools/.gitignore` - Git 忽略规则（包含 config.json）

