import json
import os
import time
from openai import OpenAI
from collections import defaultdict
from tqdm import tqdm

# ================= 配置区域 =================
# 1. 代理 (建议注释)
# os.environ["http_proxy"] = "http://127.0.0.1:7897"
# os.environ["https_proxy"] = "http://127.0.0.1:7897"

# 2. 路径 (读取脚本 1 的输出)
INPUT_RESULTS_PATH = r"D:\CVE\cwe-bench-java1\neccessary_condition_analyze.py\silicon_analysis_results.json"
FINAL_RULES_PATH = r"D:\CVE\cwe-bench-java1\neccessary_condition_analyze.py\silicon_cwe_rules.json"

# 3. API 配置
API_KEY = "sk-jhbidcgagdiogevbjgqkxkhqudyjcwltoiatzseuszpahuzu"
BASE_URL = "https://api.siliconflow.cn/v1"
MODEL_NAME = "deepseek-ai/DeepSeek-V3"
# ===========================================

def extract_json_content(text):
    """鲁棒的 JSON 提取"""
    if not text: return None
    text = text.strip()
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    if start_idx == -1 or end_idx == -1: return None
    return text[start_idx : end_idx + 1]

def synthesize():
    print(f"--- 启动归纳总结 (Model: {MODEL_NAME}) ---")
    
    if not os.path.exists(INPUT_RESULTS_PATH):
        print("[!] 请先运行脚本 1 生成分析结果")
        return

    with open(INPUT_RESULTS_PATH, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    # 1. 过滤与分组
    cwe_groups = defaultdict(list)
    valid_count = 0
    
    for item in raw_data:
        analysis = item.get("analysis", {})
        qa = analysis.get("Quality_Assessment", {})
        is_classic = qa.get("is_classic", False)
        
        # 过滤策略：只保留经典样本，或者置信度 > 7 的样本
        # 丢弃分析失败或置信度太低的噪音数据
        if analysis.get("status") == "error" or (not is_classic and qa.get("confidence", 0) <= 7):
            continue
            
        cwe = analysis.get("Inferred_CWE", "Unknown")
        if "CWE-" in cwe:
            # 简单清洗 CWE ID (例如 "CWE-22: Path Traversal" -> "CWE-22")
            base_cwe = cwe.split(":")[0].strip().split(" ")[0]
            cwe_groups[base_cwe].append(item)
            valid_count += 1

    print(f"[+] 过滤后有效样本: {valid_count} 条，覆盖 {len(cwe_groups)} 个 CWE 类别")

    # 2. 归纳
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    final_rules = []

    for cwe_id, items in tqdm(cwe_groups.items(), desc="Synthesizing"):
        if len(items) == 0: continue
        
        # 排序取前 15 个置信度最高的样本作为证据
        items.sort(key=lambda x: x['analysis'].get('Quality_Assessment', {}).get('confidence', 0), reverse=True)
        top_items = items[:15]
        
        evidence = "\n".join([f"- {i['analysis'].get('Missing_Condition')}" for i in top_items])

        system_prompt = "You are a theoretical computer science expert. Output valid JSON only."
        
        user_prompt = f"""
        Synthesize a logical failure formula for {cwe_id} based on these high-confidence samples.
        
        SAMPLES (Missing Logic):
        {evidence}
        
        TASK:
        Create a logical formula: "IF (Condition A) AND (Condition B) -> Vulnerability".
        Describe the root cause pattern abstractly.
        
        OUTPUT FORMAT (JSON):
        {{
            "cwe_id": "{cwe_id}",
            "definition": "string",
            "necessary_condition_formula": "string",
            "preventative_principle": "string"
        }}
        """
        
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            
            content = response.choices[0].message.content
            # 使用提取函数防止格式错误
            cleaned_content = extract_json_content(content)
            
            if cleaned_content:
                final_rules.append(json.loads(cleaned_content))
            
            time.sleep(1) 
            
        except Exception as e:
            tqdm.write(f"[!] Error {cwe_id}: {e}")

    # 保存最终规则
    os.makedirs(os.path.dirname(FINAL_RULES_PATH), exist_ok=True)
    with open(FINAL_RULES_PATH, 'w', encoding='utf-8') as f:
        json.dump(final_rules, f, indent=2, ensure_ascii=False)
    
    print(f"\n[√] 归纳完成: {FINAL_RULES_PATH}")

if __name__ == "__main__":
    synthesize()