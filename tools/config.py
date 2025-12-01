"""
统一配置模块 - 用于多人协作
支持多种方式设置项目根路径：
1. 环境变量 CWE_BENCH_JAVA_ROOT
2. 配置文件 config.json
3. 自动检测（基于脚本位置）
"""
import os
import json
from pathlib import Path
from typing import Optional

# 配置文件名和路径
CONFIG_DIR = Path(__file__).parent / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"

def get_repo_root() -> str:
    """
    获取项目根目录路径（优先级从高到低）：
    1. 环境变量 CWE_BENCH_JAVA_ROOT
    2. 当前目录下的 config.json 文件
    3. 自动检测（基于脚本位置，向上查找包含 data/project_info.csv 的目录）
    
    Returns:
        str: 项目根目录的绝对路径
    """
    # 方法1: 环境变量
    env_root = os.getenv("CWE_BENCH_JAVA_ROOT")
    if env_root and os.path.exists(env_root):
        data_path = os.path.join(env_root, "data", "project_info.csv")
        if os.path.exists(data_path):
            return os.path.abspath(env_root)
    
    # 方法2: 配置文件（在 tools/config 目录下查找）
    tools_dir = Path(__file__).parent
    config_path = CONFIG_DIR / "config.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                repo_root = config.get("repo_root")
                if repo_root:
                    abs_path = os.path.abspath(repo_root)
                    data_path = os.path.join(abs_path, "data", "project_info.csv")
                    if os.path.exists(data_path):
                        return abs_path
        except Exception:
            pass
    
    # 方法3: 自动检测（从 tools 目录向上查找）
    current_dir = tools_dir
    max_levels = 5  # 最多向上查找5层
    for _ in range(max_levels):
        data_path = current_dir / "data" / "project_info.csv"
        if data_path.exists():
            return str(current_dir.absolute())
        parent = current_dir.parent
        if parent == current_dir:  # 已到达根目录
            break
        current_dir = parent
    
    # 如果都找不到，返回 None（由调用者处理）
    return None

def get_nvd_api_key() -> Optional[str]:
    """
    获取 NVD API Key（优先级从高到低）：
    1. 环境变量 NVD_API_KEY
    2. 配置文件 config.json
    3. 返回 None
    
    Returns:
        Optional[str]: API Key 或 None
    """
    # 方法1: 环境变量
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        return api_key
    
    # 方法2: 配置文件
    config_path = CONFIG_DIR / "config.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                return config.get("nvd_api_key")
        except Exception:
            pass
    
    return None

def create_config_template():
    """创建配置文件模板"""
    CONFIG_DIR.mkdir(exist_ok=True)
    config_path = CONFIG_DIR / "config.json"
    
    if config_path.exists():
        print(f"配置文件已存在: {config_path}")
        return
    
    # 尝试自动检测根路径
    auto_root = get_repo_root()
    
    template = {
        "repo_root": auto_root or "请设置项目根目录路径（例如: D:/CVE/cwe-bench-java1）",
        "nvd_api_key": "可选，从 https://nvd.nist.gov/developers/request-an-api-key 申请",
        "comment": "此文件用于配置项目根路径和 API Key，支持多人协作"
    }
    
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    
    print(f"已创建配置文件模板: {config_path}")
    print("请编辑此文件，设置正确的 repo_root 路径")

if __name__ == "__main__":
    # 测试配置
    print("=== 配置测试 ===")
    repo_root = get_repo_root()
    if repo_root:
        print(f"✅ 项目根路径: {repo_root}")
        print(f"✅ data/project_info.csv 存在: {os.path.exists(os.path.join(repo_root, 'data', 'project_info.csv'))}")
    else:
        print("❌ 未找到项目根路径")
        print("提示：")
        print("  1. 设置环境变量 CWE_BENCH_JAVA_ROOT")
        print("  2. 或在 tools/config.json 中配置 repo_root")
        print("  3. 或运行此脚本创建配置文件模板")
        create_config_template()
    
    api_key = get_nvd_api_key()
    if api_key:
        print(f"✅ NVD API Key: {api_key[:10]}...")
    else:
        print("⚠️  未配置 NVD API Key（可选）")

