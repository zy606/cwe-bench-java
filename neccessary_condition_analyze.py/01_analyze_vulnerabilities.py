import json
import os
import time
from openai import OpenAI
from tqdm import tqdm
from typing import List, Dict, Optional

# ================= 配置区域 =================
# 1. 代理设置 
# SiliconFlow 是国内服务，直连速度极快。务必注释掉代理，否则可能导致连接超时或 403。
# os.environ["http_proxy"] = "http://127.0.0.1:7897"
# os.environ["https_proxy"] = "http://127.0.0.1:7897"

# 2. 路径设置
INPUT_FILE_PATH = r"D:\CVE\cwe-bench-java1\tools\output\vulnerability_code\all_cves_combined.json"
OUTPUT_FILE_PATH = r"D:\CVE\cwe-bench-java1\neccessary_condition_analyze.py\silicon_analysis_results.json"

# 3. API 配置 (SiliconFlow / DeepSeek)
API_KEY = "sk-jhbidcgagdiogevbjgqkxkhqudyjcwltoiatzseuszpahuzu"
BASE_URL = "https://api.siliconflow.cn/v1"
MODEL_NAME = "deepseek-ai/DeepSeek-V3" 

# 4. 批处理 (None 表示跑全量数据)
BATCH_SIZE = None
# ===========================================

def extract_json_content(text):
    """
    终极鲁棒版本：利用堆栈原理提取最外层的 JSON 对象。
    解决所有 'Here is json:' 前缀或 Markdown 标记残留的问题。
    """
    if not text: return None
    text = text.strip()
    
    # 快速定位：找到第一个 '{' 和最后一个 '}'
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    
    if start_idx == -1 or end_idx == -1:
        return None
        
    return text[start_idx : end_idx + 1]

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
            print(f"[+] 成功加载 {len(self.data)} 条数据")
            return True
        except Exception as e:
            print(f"[!] JSON 解析错误: {e}")
            return False

    def is_junk_file(self, file_path: str) -> bool:
        """过滤测试代码、示例代码和无关配置"""
        if not file_path: return True
        path_lower = file_path.lower()
        noise = ["/test/", "src/test", "test.java", "/example/", "/mock/", "package-info.java"]
        return any(kw in path_lower for kw in noise)

    def get_best_snippet(self, snippets: List[Dict]) -> Optional[Dict]:
        """优先选择非测试文件且代码较长的片段"""
        valid = [s for s in snippets if s.get("status") == "FOUND" 
                 and not s.get("is_missing_in_buggy_version", False) 
                 and not self.is_junk_file(s.get("file_path", "")) 
                 and len(s.get("code", "").split('\n')) >= 3]
        if not valid: return None
        # 按代码长度降序排列
        valid.sort(key=lambda x: len(x.get("code", "")), reverse=True)
        return valid[0]

class SiliconAnalyzer:
    def __init__(self, api_key, base_url, model_name):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name

    def analyze_with_retry(self, cve_item: Dict, snippet: Dict, max_retries=3) -> Dict:
        system_prompt = """
        You are a vulnerability research expert. 
        You must output strictly valid JSON. 
        """
        
        user_prompt = f"""
        Analyze this Java vulnerability code snippet.
        
        CONTEXT:
        - CVE: {cve_item.get('cve_id')}
        - Description: {cve_item.get("nvd_metadata", {}).get("description", "No description.")}
        
        CODE:
        ```java
        {snippet.get("code", "")}
        ```
        
        TASK:
        Return a JSON object with these fields:
        1. "Inferred_CWE": (String) e.g., "CWE-22".
        2. "Missing_Condition": (String) The specific logic check missing in the code.
        3. "Quality_Assessment": (Object) {{ "is_classic": boolean, "confidence": int(1-10), "reasoning": "string" }}
        
        If the code is a test file, too short, or unclear, set "is_classic": false.
        """

        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    # 强制 JSON 模式
                    response_format={"type": "json_object"},
                    temperature=0.1
                )
                
                content = response.choices[0].message.content
                # 使用鲁棒的提取函数
                cleaned_content = extract_json_content(content)
                
                if not cleaned_content:
                    raise ValueError("No JSON object found")
                    
                return json.loads(cleaned_content)
                
            except Exception as e:
                err_msg = str(e)
                # 即使是 DeepSeek，偶尔也可能波动，稍微重试
                if "429" in err_msg:
                    wait_time = 2 * (attempt + 1)
                    if attempt > 0: tqdm.write(f"\n[!] Rate Limit. Sleeping {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    # 只有最后一次重试失败才打印错误，保持界面整洁
                    if attempt == max_retries - 1:
                        tqdm.write(f"\n[!] API Error {cve_item.get('cve_id')}: {e}")
                    time.sleep(1)

        return {
            "Inferred_CWE": "Unknown",
            "Missing_Condition": "Analysis Failed",
            "Quality_Assessment": {"is_classic": False, "confidence": 0, "reasoning": "Error"},
            "status": "error"
        }

def main():
    print(f"--- 启动 SiliconFlow 分析: {MODEL_NAME} ---")
    
    # 创建输出目录
    os.makedirs(os.path.dirname(OUTPUT_FILE_PATH), exist_ok=True)
    
    processor = VulnerabilityDataProcessor(INPUT_FILE_PATH)
    if not processor.load_data(): return

    analyzer = SiliconAnalyzer(API_KEY, BASE_URL, MODEL_NAME)
    results = []
    
    target_data = processor.data[:BATCH_SIZE] if BATCH_SIZE else processor.data
    
    with tqdm(total=len(target_data), desc="Analyzing") as pbar:
        for cve in target_data:
            snippets = cve.get("code_snippets", [])
            best_snippet = processor.get_best_snippet(snippets)
            
            if not best_snippet:
                pbar.update(1)
                continue 

            analysis = analyzer.analyze_with_retry(cve, best_snippet)
            
            # 显示简报
            cwe = analysis.get('Inferred_CWE', 'N/A')
            qa = analysis.get('Quality_Assessment', {})
            is_classic = qa.get('is_classic', False)
            
            pbar.set_postfix({"ID": cve.get('cve_id'), "CWE": cwe, "Cls": is_classic})
            pbar.update(1)

            results.append({
                "cve_id": cve.get("cve_id"),
                "file_path": best_snippet.get("file_path"),
                "analysis": analysis
            })
            
            # SiliconFlow 速度快，短暂停顿即可
            time.sleep(0.5)

    with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[√] 结果已保存: {OUTPUT_FILE_PATH}")

if __name__ == "__main__":
    main()