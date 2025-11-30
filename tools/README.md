# **Integrated Vulnerability Miner for CWE-Bench-Java**

这是一个专为 [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) 数据集设计的漏洞数据挖掘工具。它整合了 **NVD (National Vulnerability Database)** 的官方元数据和 **GitHub** 的历史代码快照，旨在自动爬取 CVE 详情并利用增强算法精准提取存在漏洞的代码片段（Buggy Methods）。

## **🚀 主要功能**

1. **NVD API 深度集成**  
   * 自动根据 CVE ID 获取漏洞描述、CVSS V3 评分、严重等级（Severity）和发布日期。  
   * 内置 API Key 支持（加速请求）及自动重试机制，处理网络抖动。  
2. **智能代码提取算法 (Signature Weighted Search)**  
   * **核心痛点解决**：解决因代码版本回退导致 CSV 行号与实际代码不匹配的问题。  
   * **加权搜索**：结合方法名、方法签名（Signature）关键词和提示行号进行多维度加权评分，精准定位目标方法。  
   * **完整性保障**：使用括号平衡算法（Brace Balance Analysis）确保提取出完整的函数体，而非截断的代码片段。  
3. **灵活的运行模式**  
   * **单查模式 (Interactive)**：适合调试，输入单个 CVE ID 查看提取结果。  
   * **批量模式 (Batch)**：自动扫描 project\_info.csv，支持断点续传（自动跳过已处理的 CVE），结果实时保存。  
4. **数据清洗与结构化**  
   * 将分散的项目信息、修复定位信息、漏洞元数据整合为统一的 JSON 格式。

## **🛠️ 环境要求与安装**

### **依赖库**

本脚本基于 Python 3.8+ 开发，需要安装以下第三方库：

pip install pandas requests

### **数据集依赖**

本脚本需要放置在与 cwe-bench-java 数据集兼容的目录结构中，或手动指定数据集路径。脚本依赖以下文件：

* data/project\_info.csv: 包含 CVE ID, GitHub URL, Buggy Commit ID 等。  
* data/fix\_info.csv: 包含文件名, 方法名, 方法签名, 起止行号等。

## **⚙️ 配置说明**

在使用前，请打开脚本文件并在底部的配置区域进行修改：

if \_\_name\_\_ \== "\_\_main\_\_":  
    \# 1\. 设置 cwe-bench-java 仓库的根目录路径  
    REPO\_ROOT \= r"D:\\克隆仓库\\cwe-bench-java"  
      
    \# 2\. 设置 NVD API Key (可选，推荐配置以加快速度)  
    \# 申请地址: \[https://nvd.nist.gov/developers/request-an-api-key\](https://nvd.nist.gov/developers/request-an-api-key)  
    MY\_API\_KEY \= "your-api-key-here"   
      
    \# ...

**⚠️ 安全警告**：在将脚本提交到公开仓库（如 GitHub）之前，**请务必删除或脱敏代码中的 API Key**，防止配额被滥用。

## **🖥️ 使用指南**

运行脚本：

python vulnerability\_miner.py

根据提示选择模式：

1. **单查模式**：  
   * 输入：CVE-xxxx-xxxx  
   * 输出：final\_dataset/debug\_CVE-xxxx-xxxx.json  
   * 用途：快速验证某个特定的 CVE 是否能被正确抓取和解析。  
2. **批量模式**：  
   * 输入：确认开始 (y)  
   * 输出：final\_dataset/all\_cves\_combined.json  
   * 用途：全量处理。脚本会每处理 5 个项目自动保存一次，防止意外中断导致数据丢失。

## **📂 输出数据结构**

生成的 JSON 文件包含以下字段：

\[  
  {  
    "cve\_id": "CVE-2019-10086",  
    "project\_slug": "apache/commons-beanutils",  
    "buggy\_commit\_id": "9426f0...",  
    "github\_url": "\[https://github.com/apache/commons-beanutils\](https://github.com/apache/commons-beanutils)",  
    "nvd\_metadata": {  
      "description": "A vulnerability in Apache Commons Beanutils...",  
      "published\_date": "2019-08-20T21:15:00.000",  
      "cvss\_v3\_score": 9.8,  
      "severity": "CRITICAL"  
    },  
    "code\_snippets": \[  
      {  
        "file\_path": "src/main/java/org/apache/commons/beanutils/PropertyUtilsBean.java",  
        "class\_name": "PropertyUtilsBean",  
        "method\_name": "getNestedProperty",  
        "signature": "Object getNestedProperty(Object, String)",  
        "lines\_hint\_csv": \[76, 95\],  
        "code": "    public Object getNestedProperty(Object bean, String name) {\\n ... }",  
        "status": "FOUND",  
        "lines\_extracted": \[80, 102\],  
        "is\_missing\_in\_buggy\_version": false  
      }  
    \]  
  }  
\]

## **🔍 状态码说明**

在 code\_snippets 中，status 字段表示提取结果：

* FOUND: 成功定位并提取代码。  
* FILE\_MISSING: 无法从 GitHub Raw 链接下载文件（可能是路径错误或文件已重命名）。  
* METHOD\_MISSING: 文件存在，但在文件中找不到指定的方法名。  
* EMPTY\_BODY: 方法被找到，但无法提取内容（可能是解析错误）。

## **📝 日志系统**

脚本运行时会生成 mining.log 文件，其中记录了：

* CSV 数据加载情况。  
* 每个 CVE 的处理进度。  
* 网络请求错误或文件解析异常。

**License**: MIT

## 🤝 致谢

本工具基于 [iris-sast/cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) 数据集构建。感谢原作者整理的基础数据。