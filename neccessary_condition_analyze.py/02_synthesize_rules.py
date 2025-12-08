import json
import os
os.environ["http_proxy"] = "http://127.0.0.1:7897"
os.environ["https_proxy"] = "http://127.0.0.1:7897"
import re
import time
import google.generativeai as genai
from collections import defaultdict
from tqdm import tqdm

# ================= 配置区域 =================
# 1. 代理


# 2. 路径
INPUT_RESULTS_PATH = r"D:\CVE\cwe-bench-java1\neccessary_condition_analyze.py\gemini_analysis_results.json"
FINAL_RULES_PATH = r"D:\CVE\cwe-bench-java1\neccessary_condition_analyze.py\cwe_synthesis_rules.json"

# 3. API
API_KEY = "AIzaSyBWtDjtTNHAeqxqvD_suvjym3Te9cxH48I"
MODEL_NAME = "gemini-2.5-flash"
# ===========================================

def clean_and_parse_json(text):
    text = re.sub(r'^```json\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(text.replace('\\', '\\\\'))
        except:
            return None

def synthesize_cwe_rules():
    print(f"--- 启动择优归纳: {MODEL_NAME} ---")

    if not os.path.exists(INPUT_RESULTS_PATH):
        print(f"[!] 输入文件不存在")
        return

    with open(INPUT_RESULTS_PATH, 'r', encoding='utf-8') as f:
        raw_results = json.load(f)

    # 1. 分组并过滤 (关键步骤：只保留高质量样本)
    cwe_groups = defaultdict(list)
    for item in raw_results:
        analysis = item.get("analysis", {})
        if analysis.get("status") == "error": continue
        
        # 质量检查
        quality = analysis.get("Quality_Assessment", {})
        # 策略：必须是经典案例，或者置信度大于7
        if not quality.get("is_classic", False) and quality.get("confidence", 0) < 7:
            continue
            
        cwe_id = analysis.get("Inferred_CWE", "Unknown")
        if cwe_id and "CWE-" in cwe_id:
            base_cwe = cwe_id.split(":")[0].strip().split(" ")[0]
            cwe_groups[base_cwe].append(item)

    print(f"经过过滤，剩余 {len(cwe_groups)} 个有效 CWE 类别用于归纳。")

    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel(model_name=MODEL_NAME, generation_config={"response_mime_type": "application/json"})
    final_rules = []

    # 2. 归纳
    for cwe_id, items in tqdm(cwe_groups.items(), desc="Synthesizing"):
        if len(items) == 0: continue

        # 按置信度排序，取前10个最好的
        items.sort(key=lambda x: x['analysis'].get('Quality_Assessment', {}).get('confidence', 0), reverse=True)
        top_items = items[:10]

        evidence = "\n".join([f"- {i['analysis'].get('Missing_Condition')}" for i in top_items])
        
        prompt = f"""
        You are a security theorist. Based on these {len(top_items)} high-quality "Classic" vulnerability samples for {cwe_id}, strictly deduce the Abstract Necessary Conditions.
        
        Samples (Missing Conditions):
        {evidence}
        
        Task:
        Synthesize a logical formula. DO NOT describe the code. Describe the LOGIC constraints.
        
        Output JSON (No backslashes):
        {{
            "cwe_id": "{cwe_id}",
            "definition": "...",
            "necessary_condition_formula": "IF (Input reaches sink) AND (Validation X is missing) -> Vulnerability",
            "root_cause_pattern": "..."
        }}
        """
        
        try:
            response = model.generate_content(prompt)
            rule = clean_and_parse_json(response.text)
            if rule: final_rules.append(rule)
            time.sleep(2)
        except Exception as e:
            tqdm.write(f"[!] Error {cwe_id}: {e}")

    with open(FINAL_RULES_PATH, 'w', encoding='utf-8') as f:
        json.dump(final_rules, f, indent=2, ensure_ascii=False)
    
    print(f"\n[√] 归纳完成: {FINAL_RULES_PATH}")

if __name__ == "__main__":
    synthesize_cwe_rules()