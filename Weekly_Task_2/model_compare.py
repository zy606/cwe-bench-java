import os
import json
import random
import numpy as np
import torch
from sentence_transformers import CrossEncoder

# 1. 设置镜像加速
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

# 辅助函数
def format_context_input(item):
    """
    带上下文的输入格式：消耗 token 用于提供元数据
    """
    return f"File: {item['path']}\nMethod: {item['method']}\nCode:\n{item['code']}"

def clean_code_input(item):
    """
    纯代码输入格式：尽可能多地保留代码逻辑
    """
    return item['code'].strip()

def select_best_snippet(cve_item):
    """
    智能选择 Ground Truth (保持不变)
    """
    snippets = cve_item.get('code_snippets', [])
    description = cve_item['nvd_metadata']['description'].lower()
    
    best_snippet = None
    max_score = -100
    
    risk_keywords = ["unzip", "extract", "parse", "eval", "exec", "query", "validate", "sanitize", "deserialize"]
    generic_keywords = ["file", "run", "main", "setup", "teardown", "test", "dummy", "get", "set"]

    for s in snippets:
        if not s.get('code', '').strip(): continue
        method_name = s['method_name']
        m_name_lower = method_name.lower()
        score = 0
        
        if m_name_lower in description and len(m_name_lower) > 3: score += 10
        if any(k in m_name_lower for k in risk_keywords): score += 5
        if any(k == m_name_lower for k in generic_keywords): score -= 10
        score += min(len(s['code']) / 1000, 2)
        if "test" in s.get('file_path', '').lower(): score -= 2
        
        if score > max_score:
            max_score = score
            best_snippet = s
            
    if not best_snippet and snippets:
        best_snippet = next((s for s in snippets if s.get('code', '').strip()), None)
    return best_snippet

# 主程序

current_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(current_dir, 'final_dataset', 'all_cves_combined.json')

print(f"📂 读取数据: {json_path}")
try:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except Exception as e:
    print(f"❌ 读取失败: {e}")
    exit()

# 数据清洗
valid_cves = []
for item in data:
    valid_snippets = [s for s in item.get('code_snippets', []) if not s.get('is_missing_in_buggy_version', False) and s.get('code', '').strip()]
    if valid_snippets:
        item['code_snippets'] = valid_snippets
        valid_cves.append(item)

if not valid_cves:
    print("❌ 数据集为空！")
    exit()

print(f"✅ 有效样本数: {len(valid_cves)}")

# 4. 加载模型
print("\n 正在加载模型群...")
device = "cuda" if torch.cuda.is_available() else "cpu"

# 模型 A: Baseline
print(f"   🔹 模型 A (Base): ms-marco-MiniLM-L-6-v2")
model_base = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2', max_length=512, device=device)

# 模型 B: CodeBERT (我们将用它跑两遍：一遍带Context，一遍不带)
print(f"   🔹 模型 B (Code): codebert-cross-encoder (Shared for Ctx/Raw)")
model_codebert = CrossEncoder('alexandraroze/codebert-cross-encoder', max_length=512, device=device)

# 模型 C: BGE-M3
print(f"   🔹 模型 C (BGE ): bge-reranker-v2-m3")
model_args = {'torch_dtype': torch.float16} if device == "cuda" else {}
model_bge = CrossEncoder('BAAI/bge-reranker-v2-m3', max_length=1024, automodel_args=model_args, device=device)

# ==========================================
# 5. 对比测试循环
# ==========================================
NUM_ROUNDS = 10 
test_cases = random.sample(valid_cves, min(NUM_ROUNDS, len(valid_cves)))

print(f"\n 比较开启! (Code-Ctx = 带前缀, Code-Raw = 纯代码)\n")
# 表头调整
print(f"{'CVE ID':<14} | {'Base':<4} | {'Code-Ctx':<8} | {'Code-Raw':<8} | {'BGE':<4} | {'Winner':<8}")
print("-" * 75)

# 记录排名
ranks = {'base': [], 'code_ctx': [], 'code_raw': [], 'bge': []}

for cve in test_cases:
    cve_id = cve['cve_id']
    query = cve['nvd_metadata']['description']
    
    # 准备样本
    target = select_best_snippet(cve)
    if not target: continue
    
    candidates = [{'code': target['code'], 'method': target['method_name'], 'path': target['file_path'], 'label': 'True'}]
    
    others = [x for x in valid_cves if x['cve_id'] != cve_id]
    distractors = random.sample(others, min(9, len(others)))
    for d in distractors:
        ds = random.choice(d['code_snippets'])
        candidates.append({'code': ds['code'], 'method': ds['method_name'], 'path': ds['file_path'], 'label': 'False'})
        
    random.shuffle(candidates)
    
    # --- 构造输入 ---
    # 1. 纯代码输入 (Base & Code-Raw)
    inputs_raw = [[query, clean_code_input(item)] for item in candidates]
    
    # 2. 带上下文输入 (Code-Ctx & BGE)
    inputs_ctx = [[query, format_context_input(item)] for item in candidates]
    
    # --- 推理 ---
    scores_base = model_base.predict(inputs_raw)
    scores_code_ctx = model_codebert.predict(inputs_ctx)      # CodeBERT 方案1
    scores_code_raw = model_codebert.predict(inputs_raw)      # CodeBERT 方案2
    scores_bge = model_bge.predict(inputs_ctx)
    
    # --- 排名计算 ---
    def get_rank(scores, candidates):
        ranked_indices = np.argsort(scores)[::-1]
        for r, idx in enumerate(ranked_indices):
            if candidates[idx]['label'] == 'True': return r + 1
        return -1

    r_base = get_rank(scores_base, candidates)
    r_ctx = get_rank(scores_code_ctx, candidates)
    r_raw = get_rank(scores_code_raw, candidates)
    r_bge = get_rank(scores_bge, candidates)
    
    ranks['base'].append(r_base)
    ranks['code_ctx'].append(r_ctx)
    ranks['code_raw'].append(r_raw)
    ranks['bge'].append(r_bge)
    
    # 判定本轮胜者
    best_rank = min(r_base, r_ctx, r_raw, r_bge)
    winners = []
    if r_base == best_rank: winners.append("Base")
    if r_ctx == best_rank: winners.append("Ctx")
    if r_raw == best_rank: winners.append("Raw")
    if r_bge == best_rank: winners.append("BGE")
    
    print(f"{cve_id:<14} | {r_base:<4} | {r_ctx:<8} | {r_raw:<8} | {r_bge:<4} | {'/'.join(winners):<8}")

# ==========================================
# 6. 最终统计
# ==========================================
def print_stats(name, r_list):
    mrr = np.mean([1/r for r in r_list])
    avg = np.mean(r_list)
    print(f"{name:<20} | {avg:<15.2f} | {mrr:<15.2f}")

print("-" * 75)
print("\n📊 最终结果:")
print(f"{'Model Configuration':<20} | {'Avg Rank (↓)':<15} | {'MRR (↑)':<15}")
print("-" * 55)
print_stats("Baseline (MiniLM)", ranks['base'])
print_stats("CodeBERT (Context)", ranks['code_ctx'])
print_stats("CodeBERT (Raw)", ranks['code_raw'])
print_stats("BGE-M3 (SOTA)", ranks['bge'])
print("-" * 55)