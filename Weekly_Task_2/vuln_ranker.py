import os
import json
import random
import re
import torch
from sentence_transformers import CrossEncoder

# 1. 设置环境变量 (如果需要)
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

# 推荐使用 BGE-Reranker-v2-m3，支持多语言和代码，且支持 8192 长度
MODEL_NAME = 'BAAI/bge-reranker-v2-m3' 
# 如果显存不够 (小于 8G)，可以改用 'BAAI/bge-reranker-base'
DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'final_dataset', 'all_cves_combined.json')

# 辅助函数：代码清洗
def clean_code(code_str):
    """
    简单的代码清洗，去除多余的空行和首尾空格，节省 Token。
    """
    if not code_str: return ""
    # 去除多余空行
    code_str = re.sub(r'\n\s*\n', '\n', code_str)
    return code_str.strip()

# 核心逻辑：智能代码选择器
def select_best_snippet(cve_item):
    """
    从 CVE 的多个代码片段中选出最符合描述的一个。
    """
    snippets = cve_item.get('code_snippets', [])
    description = cve_item['nvd_metadata']['description'].lower()
    
    best_snippet = None
    max_score = -9999
    
    # 增加针对 Java/C++ 的高危操作词
    risk_keywords = [
        "unzip", "extract", "parse", "eval", "exec", "query", "validate", 
        "sanitize", "deserialize", "upload", "authentication", "xml", "sql"
    ]
    # 增加无意义代码的过滤
    generic_keywords = ["dummy", "test", "demo", "example", "setup", "teardown"]

    print(f"\n🕵️‍♂️ 正在从 {len(snippets)} 个片段中筛选 Ground Truth...")

    for s in snippets:
        raw_code = s.get('code', '')
        if not raw_code.strip():
            continue
            
        method_name = s['method_name']
        m_name_lower = method_name.lower()
        score = 0
        
        # 规则 1: 描述中直接包含了函数名 (最强特征)
        # 例如描述: "Vulnerability in doSomething function..."
        if m_name_lower in description and len(m_name_lower) > 3:
            score += 20
        
        # 规则 2: 文件路径匹配
        # 有时描述会说 "In directory/file.java"，如果片段属于该文件则加分
        file_path = s.get('file_path', '').lower()
        if any(part in description for part in file_path.split('/') if len(part) > 4):
            score += 5

        # 规则 3: 代码内容包含高危关键词
        if any(k in m_name_lower for k in risk_keywords):
            score += 5
        
        # 规则 4: 惩罚测试代码 (通常 CVE 描述的是业务逻辑，而不是测试用例)
        if "test" in file_path or "test" in m_name_lower:
            score -= 5
        if any(k == m_name_lower for k in generic_keywords):
            score -= 10
            
        # 规则 5: 代码长度适中优先 (太短的往往是接口定义，太长的可能是整个类)
        code_len = len(raw_code)
        if 50 < code_len < 3000:
            score += 2
        elif code_len < 50: # 太短
            score -= 5

        if score > max_score:
            max_score = score
            best_snippet = s

    # 失败，选择第一个
    if not best_snippet and snippets:
        best_snippet = snippets[0]
        
    return best_snippet

# 主程序

print(f"📂 正在读取数据: {DATA_PATH}")
try:
    with open(DATA_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"❌ 错误：找不到文件。")
    exit()

# 数据预处理
valid_cves = []
for item in data:
    valid_snippets = [
        s for s in item.get('code_snippets', []) 
        if not s.get('is_missing_in_buggy_version', False) and s.get('code', '').strip()
    ]
    if valid_snippets:
        item['code_snippets'] = valid_snippets
        valid_cves.append(item)

if not valid_cves:
    print("❌ 数据集为空！")
    exit()

print(f"✅ 数据加载完成，共有 {len(valid_cves)} 个有效 CVE 样本。")

# 加载模型
print(f"🤖 正在加载 Rank 模型: {MODEL_NAME} ... ")
device = "cuda" if torch.cuda.is_available() else "cpu"

# BGE-Reranker 使用 CrossEncoder 接口加载时需要注意：
# automodel_args={'torch_dtype': torch.float16} 可以加速推理并减少显存（仅限 GPU）
model_args = {'torch_dtype': torch.float16} if device == "cuda" else {}
model = CrossEncoder(
    MODEL_NAME, 
    max_length=1024, # BGE-M3 支持 8192，但为了速度设为 1024 通常足够，不够可调大
    automodel_args=model_args,
    device=device
)

while True:
    print("\n" + "="*80)
    print("可用 CVE 示例: " + ", ".join([x['cve_id'] for x in valid_cves[:5]]) + " ...")
    user_input = input("👉 请输入目标 CVE 编号 (输入 q 退出, r 随机): ").strip().upper()
    
    if user_input == 'Q':
        break
    
    if user_input == 'R':
        target_sample = random.choice(valid_cves)
    else:
        target_sample = next((item for item in valid_cves if item["cve_id"] == user_input), None)
    
    if not target_sample:
        print(f"❌ 未找到 {user_input}。")
        continue

    # 准备数据
    cve_id = target_sample['cve_id']
    description = target_sample['nvd_metadata']['description']
    
    # 提取 Ground Truth
    true_snippet = select_best_snippet(target_sample)
    true_code = clean_code(true_snippet['code'])
    true_method = true_snippet['method_name']

    print(f"\nTarget CVE: {cve_id}")
    print(f"Description: {description[:150]}...")
    print(f"Ground Truth Method: {true_method}")

    # 构建候选集
    candidates = [{
        'code': true_code, 
        'label': '✅ True', 
        'id': cve_id, 
        'method': true_method
    }]
    
    # 构建干扰项 (Hard Negatives: 选择其他 CVE 的代码)
    other_samples = [x for x in valid_cves if x['cve_id'] != cve_id]
    distractors = random.sample(other_samples, min(9, len(other_samples)))
    
    for noise in distractors:
        # 随机取一个干扰代码
        noise_snippet = random.choice(noise['code_snippets'])
        candidates.append({
            'code': clean_code(noise_snippet['code']), 
            'label': '❌ False',
            'id': noise['cve_id'],
            'method': noise_snippet['method_name']
        })
    
    # 打乱顺序
    random.shuffle(candidates)

    # 构造模型输入对 (Query, Document)
    model_inputs = [[description, item['code']] for item in candidates]
    
    print(f"⏳ 正在计算语义相似度 (使用 {device})...")
    scores = model.predict(model_inputs)
    
    # 归一化分数 (Sigmoid)，方便阅读 (BGE 输出是 logits，范围可能是负无穷到正无穷)
    # 简单的 sigmoid 实现
    sigmoid_scores = [1 / (1 + 2.71828 ** (-s)) for s in scores]
    
    ranked_results = sorted(zip(candidates, scores, sigmoid_scores), key=lambda x: x[1], reverse=True)

    # 输出结果
    print(f"\n{'Rank':<4} | {'Logit':<8} | {'Prob':<6} | {'Type':<10} | {'Method Name'}")
    print("-" * 70)

    found_rank = -1
    for rank, (item, raw_score, prob) in enumerate(ranked_results):
        rank_num = rank + 1
        is_target = item['label'].startswith('✅')
        if is_target: found_rank = rank_num
        
        # 截断方法名显示
        method_disp = (item['method'][:35] + '..') if len(item['method']) > 35 else item['method']
        
        print(f"{rank_num:<4} | {raw_score:<8.2f} | {prob:<6.2f} | {item['label']:<10} | {method_disp}")

    print("-" * 70)
    if found_rank == 1:
        print(f"🎉 完美匹配！Ground Truth 排在第 1 位。")
    elif found_rank <= 3:
        print(f"👌 效果尚可。Ground Truth 排在第 {found_rank} 位。")
    else:
        print(f"⚠️ 效果不佳。Ground Truth 排在第 {found_rank} 位。可能代码与描述的语义差距过大。")