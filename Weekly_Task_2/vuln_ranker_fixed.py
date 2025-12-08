import os
import json
import random
import numpy as np

# 1. 设置镜像加速
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

from sentence_transformers import CrossEncoder

# ==========================================
# 核心逻辑：智能代码选择器
# ==========================================
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

    print(f"\n🕵️‍♂️ 正在分析 {len(snippets)} 个候选片段...")

    for s in snippets:
        method_name = s['method_name']
        # 跳过空代码
        if not s.get('code', '').strip():
            continue
            
        m_name_lower = method_name.lower()
        score = 0
        
        # 规则 1: 方法名直接出现在漏洞描述中 (最强特征)
        # 比如描述里说 "The unzip function...", 方法名也是 "unzip"
        if m_name_lower in description and len(m_name_lower) > 3:
            score += 10
            
        # 规则 2: 方法名包含高危操作关键词
        if any(k in m_name_lower for k in risk_keywords):
            score += 5
            
        # 规则 3: 方法名是通用无意义词汇 (降权)
        if any(k == m_name_lower for k in generic_keywords):
            score -= 10
        
        # 规则 4: 优先选择代码较长的 (通常逻辑更复杂，不像 wrapper)
        code_len = len(s['code'])
        score += min(code_len / 1000, 2) # 最多加 2 分
        
        print(f"   - 候选: {method_name:<20} | 得分: {score:.1f}")
        
        if score > max_score:
            max_score = score
            best_snippet = s

    # 兜底：如果没算出来，就默认取第一个
    if not best_snippet and snippets:
        best_snippet = snippets[0]
        print("   ⚠️ 无明显特征，回退到默认第一个片段")
        
    return best_snippet

# ==========================================
# 主程序
# ==========================================

# 2. 路径处理
current_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(current_dir, 'final_dataset', 'all_cves_combined.json')

print(f"📂 正在读取数据: {json_path}")
try:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"❌ 错误：找不到文件。请确保文件位于: {json_path}")
    exit()

# 3. 数据清洗 (过滤掉 invalid code)
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

print(f"✅ 数据加载完成，共有 {len(valid_cves)} 个有效 CVE 样本。")

# 4. 加载模型
model_name = 'cross-encoder/ms-marco-MiniLM-L-6-v2'
print(f"🤖 正在加载 Rank 模型: {model_name} ...")
model = CrossEncoder(model_name, max_length=512)

# ==========================================
# 5. 交互式循环
# ==========================================
while True:
    print("\n" + "="*50)
    print("可用 CVE 示例: " + ", ".join([x['cve_id'] for x in valid_cves[:5]]) + " ...")
    user_input = input("👉 请输入目标 CVE 编号 (输入 q 退出): ").strip().upper()
    
    if user_input == 'Q':
        print("Bye!")
        break
        
    # 查找目标 CVE
    target_sample = next((item for item in valid_cves if item["cve_id"] == user_input), None)
    
    if not target_sample:
        print(f"❌ 未找到 {user_input}，请检查拼写或尝试列表中的 ID。")
        continue

    # --- 智能选择 ---
    cve_id = target_sample['cve_id']
    query = target_sample['nvd_metadata']['description']
    
    # 调用上面的智能选择函数
    true_code_snippet = select_best_snippet(target_sample)
    true_code = true_code_snippet['code']
    true_method = true_code_snippet['method_name']

    print(f"\n------------------------------------------")
    print(f"🎯 选定目标: {cve_id}")
    print(f"📄 漏洞描述: {query[:120]}...")
    print(f"🧠 智能选中: 方法 [{true_method}] (得分最高)")
    print(f"------------------------------------------")

    # --- 构建候选列表 ---
    candidates = [{'code': true_code, 'label': 'True (Target)', 'id': cve_id, 'method': true_method}]
    
    # 随机抽取 9 个干扰项
    other_samples = [x for x in valid_cves if x['cve_id'] != cve_id]
    # 如果样本不够9个，取全部
    sample_count = min(9, len(other_samples))
    if sample_count > 0:
        distractors = random.sample(other_samples, sample_count)
        for noise in distractors:
            # 干扰项随机取一个即可，或者也可以用 select_best_snippet 增加难度
            noise_snippet = random.choice(noise['code_snippets'])
            candidates.append({
                'code': noise_snippet['code'], 
                'label': 'False (Distractor)',
                'id': noise['cve_id'],
                'method': noise_snippet['method_name']
            })
    
    # 补足到 10 个 (防止数据太少)
    while len(candidates) < 10:
         candidates.append({'code': "public void dummy(){}", 'label': 'False (Padding)', 'id': 'Noise', 'method': 'dummy'})

    random.shuffle(candidates)

    # --- 预测与排序 ---
    model_inputs = [[query, item['code']] for item in candidates]
    print(f"⏳ 正在对 {len(candidates)} 个代码片段进行排序...")
    scores = model.predict(model_inputs)
    ranked_results = sorted(zip(candidates, scores), key=lambda x: x[1], reverse=True)

    # --- 输出结果 ---
    print(f"\n{'Rank':<4} | {'Score':<8} | {'Type':<18} | {'ID':<15} | {'Method Name'}")
    print("-" * 85)

    found_rank = -1
    for rank, (item, score) in enumerate(ranked_results):
        rank_num = rank + 1
        is_target = item['label'].startswith('True')
        prefix = "✅" if is_target else "  "
        if is_target: found_rank = rank_num
        
        print(f"{prefix} {rank_num:<2} | {score:.4f}   | {item['label']:<18} | {item['id']:<15} | {item['method']}")

    print("-" * 85)
    if found_rank == 1:
        print(f"🎉 成功！模型将目标 ({true_method}) 排在第 1 位。")
    else:
        print(f"⚠️ 目标排在第 {found_rank} 位。请检查描述是否过于隐晦，或干扰项是否太强。")