import json
import os
os.environ["http_proxy"] = "http://127.0.0.1:7897"
os.environ["https_proxy"] = "http://127.0.0.1:7897"
import time
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from tqdm import tqdm
from typing import List, Dict, Optional

# ================= 配置区域 =================
# 1. 代理


# 2. 路径
INPUT_FILE_PATH = r"D:\CVE\cwe-bench-java1\tools\output\vulnerability_code\all_cves_combined.json"
OUTPUT_FILE_PATH = r"D:\CVE\cwe-bench-java1\neccessary_condition_analyze.py\gemini_analysis_results.json"

# 3. API
API_KEY = "AIzaSyBWtDjtTNHAeqxqvD_suvjym3Te9cxH48I"
MODEL_NAME = "gemini-2.5-flash"

# 4. 批处理 (10个用于快速测试，正式跑可改大)
BATCH_SIZE = None
# ===========================================

class VulnerabilityDataProcessor:
    def __init__(self, input_path):
        self.input_path = input_path
        self.data = []

    def load_data(self):
        if not os.path.exists(self.input_path):
            print(f"[!] 输入文件不存在: {self.input_path}")
            return False
        try:
            with open(self.input_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            return True
        except Exception as e:
            print(f"[!] JSON 解析错误: {e}")
            return False

    def is_junk_file(self, file_path: str) -> bool:
        if not file_path: return True
        path_lower = file_path.lower()
        noise_keywords = ["/test/", "/tests/", "src/test", "test.java", "/example/", "/mock/", "package-info.java"]
        return any(kw in path_lower for kw in noise_keywords)

    def get_best_snippet(self, snippets: List[Dict]) -> Optional[Dict]:
        valid_snippets = []
        for s in snippets:
            if s.get("status") == "FOUND" and \
               not s.get("is_missing_in_buggy_version", False) and \
               not self.is_junk_file(s.get("file_path", "")) and \
               len(s.get("code", "").split('\n')) >= 3:
                valid_snippets.append(s)
        if not valid_snippets: return None
        valid_snippets.sort(key=lambda x: len(x.get("code", "")), reverse=True)
        return valid_snippets[0]

class GeminiAnalyzer:
    def __init__(self, api_key, model_name):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name=model_name, generation_config={"response_mime_type": "application/json"})

    def analyze_with_retry(self, cve_item: Dict, snippet: Dict, max_retries=3) -> Dict:
        prompt = f"""
        You are a vulnerability research expert. Analyze this Java code.
        
        # Context
        - CVE: {cve_item.get('cve_id')}
        - Description: {cve_item.get("nvd_metadata", {}).get("description", "No description.")}
        
        # Code
        ```java
        {snippet.get("code", "")}
        ```
        
        # Tasks (Strict JSON Output)
        1. **Inferred_CWE**: Likely CWE ID (e.g., "CWE-22").
        2. **Missing_Condition**: What check is missing? (Logic level, not code level).
        3. **Quality_Assessment**:
           - "is_classic": true if this is a textbook example, false if it's obscure/complex/config-based.
           - "confidence": 1-10 score. Is the code snippet sufficient to see the bug?
        
        Response JSON Structure:
        {{
            "Inferred_CWE": "...",
            "Trigger_Point": "...",
            "Missing_Condition": "...",
            "Quality_Assessment": {{
                "is_classic": true/false,
                "confidence": 8
            }}
        }}
        """

        safety_settings = {k: HarmBlockThreshold.BLOCK_NONE for k in [
            HarmCategory.HARM_CATEGORY_HATE_SPEECH, HarmCategory.HARM_CATEGORY_HARASSMENT,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT
        ]}

        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(prompt, safety_settings=safety_settings)
                return json.loads(response.text)
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower():
                    time.sleep(65)
                else:
                    time.sleep(2)
        return {"status": "error"}

def main():
    print(f"--- 启动智能分析: {MODEL_NAME} ---")
    os.makedirs(os.path.dirname(OUTPUT_FILE_PATH), exist_ok=True)
    
    processor = VulnerabilityDataProcessor(INPUT_FILE_PATH)
    if not processor.load_data(): return

    analyzer = GeminiAnalyzer(API_KEY, MODEL_NAME)
    results = []
    
    # 批处理
    target_data = processor.data[:BATCH_SIZE] if BATCH_SIZE else processor.data
    
    for cve in tqdm(target_data, desc="Analyzing"):
        best_snippet = processor.get_best_snippet(cve.get("code_snippets", []))
        if not best_snippet: continue 

        analysis = analyzer.analyze_with_retry(cve, best_snippet)
        
        # 打印是否为经典样本，方便观察
        is_classic = analysis.get("Quality_Assessment", {}).get("is_classic", False)
        tqdm.write(f" -> {cve.get('cve_id')}: {analysis.get('Inferred_CWE')} (Classic: {is_classic})")

        results.append({
            "cve_id": cve.get("cve_id"),
            "file_path": best_snippet.get("file_path"),
            "analysis": analysis
        })
        time.sleep(2)

    with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[√] 结果已保存至: {OUTPUT_FILE_PATH}")

if __name__ == "__main__":
    main()