import os
import json
import random
import numpy as np

# 1. 设置镜像加速
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

from sentence_transformers import CrossEncoder

# 核心逻辑：智能代码选择器
def select_best_snippet(cve_item):
    """
    遍历一个 CVE 的所有代码片段，通过启发式评分找到最可能是漏洞逻辑的那个。
    不再只是盲目选第一个。
    """
    snippets = cve_item.get('code_snippets', [])
    description = cve_item['nvd_metadata']['description'].lower()
    
    best_snippet = None
    max_score = -100
    
    # 定义高危关键词 (加分项)
    risk_keywords = ["unzip", "extract", "parse", "eval", "exec", "query", "validate", "sanitize", "deserialize"]
    # 定义通用干扰词 (减分项)
    generic_keywords = ["file", "run", "main", "setup", "teardown", "test", "dummy", "get", "set"]

    for s in snippets:
        method_name = s['method_name']
        # 跳过空代码
        if not s.get('code', '').strip():
            continue
            
        m_name_lower = method_name.lower()
        score = 0
        
        # 规则 1: 方法名直接出现在漏洞描述中 (最强特征)
        if m_name_lower in description and len(m_name_lower) > 3:
            score += 10
            
        # 规则 2: 方法名包含高危操作关键词
        if any(k in m_name_lower for k in risk_keywords):
            score += 5
            
        # 规则 3: 方法名是通用无意义词汇 (降权)
        if any(k == m_name_lower for k in generic_keywords):
            score -= 10
        
        # 规则 4: 优先选择代码较长的
        code_len = len(s['code'])
        score += min(code_len / 1000, 2)
        
        if "test" in s.get('file_path', '').lower(): 
            score -= 2
        
        if score > max_score:
            max_score = score
            best_snippet = s
            
    if not best_snippet and snippets:
        best_snippet = next((s for s in snippets if s.get('code', '').strip()), None)
        
    return best_snippet

# 主程序

# 2. 路径处理
current_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(current_dir, 'final_dataset', 'all_cves_combined.json')

print(f"📂 读取数据: {json_path}")
try:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except Exception as e:
    print(f"❌ 读取失败: {e}")
    exit()

# 3. 数据清洗
valid_cves = []
for item in data:
    valid_snippets = [
        s for s in item.get('code_snippets', []) 
        if not s.get('is_missing_in_buggy_version', False) and s.get('code', '').strip()
    ]
    if valid_snippets:
        item_copy = item.copy()
        item_copy['code_snippets'] = valid_snippets
        valid_cves.append(item_copy)

if not valid_cves:
    print("❌ 数据集为空！")
    exit()

print(f"✅ 有效样本数: {len(valid_cves)}")

# 4. 加载模型
print("\n 正在加载模型...")
model_baseline_name = 'cross-encoder/ms-marco-MiniLM-L-6-v2'
model_sota_name = 'alexandraroze/codebert-cross-encoder'

print(f"   🔹 模型 A (Baseline): {model_baseline_name} ...")
model_baseline = CrossEncoder(model_baseline_name, max_length=512)

print(f"   🔹 模型 B (StrongCtx): {model_sota_name} ...")
model_sota = CrossEncoder(model_sota_name, max_length=512)

NUM_ROUNDS = 10 
test_cases = random.sample(valid_cves, min(NUM_ROUNDS, len(valid_cves)))

# --- 打印表头 ---
print(f"\n 比较开始! 共 {len(test_cases)} 轮比较 (每轮 1 正样本 vs 9 负样本)\n")
print(f"{'CVE ID':<16} | {'Method':<15} | {'Rank (Base)':<12} | {'Rank (SOTA)':<12} | {'Winner':<10}")
print("-" * 80)

baseline_ranks = []
sota_ranks = []

for cve in test_cases:
    cve_id = cve['cve_id']
    query = cve['nvd_metadata']['description']
    
    # 1. 准备 Target
    target_snippet = select_best_snippet(cve)
    if not target_snippet: continue
    
    candidates = [{
        'code': target_snippet['code'],
        'method': target_snippet['method_name'],
        'path': target_snippet['file_path'],
        'label': 'True'
    }]
    
    # 2. 准备 Distractors
    others = [x for x in valid_cves if x['cve_id'] != cve_id]
    distractors = random.sample(others, min(9, len(others)))
    
    for d in distractors:
        # 随机取一个非空片段作为干扰
        ds = random.choice(d['code_snippets'])
        candidates.append({
            'code': ds['code'],
            'method': ds['method_name'],
            'path': ds['file_path'],
            'label': 'False'
        })
        
    random.shuffle(candidates)
    
    # 3. 模型 A 输入构造 (Query + Code)
    inputs_baseline = [[query, item['code']] for item in candidates]
    
    # 4. 模型 B 输入构造 (Query + Strong Context)
    inputs_sota = []
    for item in candidates:
        context = f"File: {item['path']}\nMethod: {item['method']}\nCode:\n{item['code']}"
        inputs_sota.append([query, context])
        
    # 5. 推理
    scores_baseline = model_baseline.predict(inputs_baseline)
    scores_sota = model_sota.predict(inputs_sota)
    
    # 6. 计算排名
    # Baseline 排名
    ranked_indices_base = np.argsort(scores_baseline)[::-1]
    rank_base = -1
    for r, idx in enumerate(ranked_indices_base):
        if candidates[idx]['label'] == 'True':
            rank_base = r + 1
            break
            
    # SOTA 排名
    ranked_indices_sota = np.argsort(scores_sota)[::-1]
    rank_sota = -1
    for r, idx in enumerate(ranked_indices_sota):
        if candidates[idx]['label'] == 'True':
            rank_sota = r + 1
            break
            
    baseline_ranks.append(rank_base)
    sota_ranks.append(rank_sota)
    
    # 判定胜负 (移除手动空格，使用纯文本)
    if rank_sota < rank_base: 
        winner = "SOTA"
    elif rank_sota > rank_base: 
        winner = "Base"
    else: 
        winner = "Draw"
    
    # 打印单行结果
    method_display = target_snippet['method_name'][:15]
    print(f"{cve_id:<16} | {method_display:<15} | {rank_base:<12} | {rank_sota:<12} | {winner:<10}")

# --- 最终统计 ---
mrr_base = np.mean([1/r for r in baseline_ranks])
mrr_sota = np.mean([1/r for r in sota_ranks])
avg_base = np.mean(baseline_ranks)
avg_sota = np.mean(sota_ranks)

print("-" * 80)
print("\n 最终结果:")
print(f"1. 平均排名 (Lower is Better): Baseline = {avg_base:.2f}  vs  SOTA = {avg_sota:.2f}")
print(f"2. MRR 指标 (Higher is Better): Baseline = {mrr_base:.2f}  vs  SOTA = {mrr_sota:.2f}")

if avg_sota < avg_base:
    print("\n✅ 结论: CodeBERT + 强上下文 (File/Method) 显著优于 通用模型 + 纯代码。")
    print("   建议使用 SOTA 方案。")
else:
    print("\n✅ 结论: 通用模型 + 纯代码 显著优于 CodeBERT + 强上下文 (File/Method)。")
    print("   建议使用 Base 方案。")