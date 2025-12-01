#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""测试配置模块"""
import sys
import os
from pathlib import Path

# 添加 tools 目录到路径（config.py 在 tools 根目录）
tools_dir = Path(__file__).parent.parent
sys.path.insert(0, str(tools_dir))

try:
    from config import get_repo_root, get_nvd_api_key
    
    print("=== 配置测试 ===")
    root = get_repo_root()
    api_key = get_nvd_api_key()
    
    if root:
        print(f"✅ 项目根路径: {root}")
        csv_path = os.path.join(root, "data", "project_info.csv")
        print(f"✅ CSV 文件存在: {os.path.exists(csv_path)}")
    else:
        print("❌ 未找到项目根路径")
    
    if api_key:
        print(f"✅ NVD API Key: {api_key[:10]}...")
    else:
        print("⚠️  NVD API Key 未配置（可选）")
    
    print("\n=== 测试脚本导入 ===")
    try:
        from Vulnerability_Code_Extractor import IntegratedVulnMiner
        print("✅ Vulnerability_Code_Extractor 导入成功")
        
        if root:
            miner = IntegratedVulnMiner(root, nvd_api_key=api_key)
            print(f"✅ 初始化成功，项目数: {len(miner.df_project)}")
    except Exception as e:
        print(f"❌ 导入失败: {e}")
        import traceback
        traceback.print_exc()
        
except ImportError as e:
    print(f"❌ 配置模块导入失败: {e}")
    print("提示: 确保在 tools 目录下运行此脚本")

