import pandas as pd
import requests
import logging
import os
import json
import time
import re
from pathlib import Path
from typing import List, Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ================= 配置日志系统 =================
# 获取脚本所在目录（tools 目录）
TOOLS_DIR = Path(__file__).parent
# 创建日志目录（确保在 tools 目录下）
log_dir = TOOLS_DIR / "output" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "vuln_code_miner.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IntegratedVulnMiner:
    
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, repo_root: str, nvd_api_key: Optional[str] = None):
        self.root = Path(repo_root)
        self.project_csv = self.root / "data" / "project_info.csv"
        self.fix_info_csv = self.root / "data" / "fix_info.csv"
        
        # 结果保存配置（确保在 tools 目录下）
        self.output_dir = TOOLS_DIR / "output" / "vulnerability_code_legacy"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.combined_file_path = self.output_dir / "all_cves_combined.json"

        # 网络配置
        self.api_key = nvd_api_key
        self.headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        self.nvd_delay = 1.0 if self.api_key else 6.0
        
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        # 加载数据
        logger.info("正在加载 CSV 数据表...")
        try:
            self.df_project = pd.read_csv(self.project_csv)
            self.df_fix = pd.read_csv(self.fix_info_csv)
            logger.info(f"数据加载完成。项目总数: {len(self.df_project)}")
        except Exception as e:
            logger.error(f"加载 CSV 失败: {e}")
            raise

    # ================= 1. NVD 信息获取 =================
    def fetch_nvd_info(self, cve_id: str) -> Dict:
        cve_id = cve_id.strip().upper()
        empty_info = {"description": "N/A", "published_date": None, "cvss_v3_score": None, "severity": None}
        try:
            time.sleep(self.nvd_delay)
            resp = self.session.get(self.NVD_BASE_URL, headers=self.headers, params={"cveId": cve_id}, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns: return empty_info
                cve_item = vulns[0].get("cve", {})
                desc = "No description"
                for d in cve_item.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value")
                        break
                metrics = cve_item.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [])
                score = None
                severity = None
                if cvss_data:
                    metric_data = cvss_data[0].get("cvssData", {})
                    score = metric_data.get("baseScore")
                    severity = metric_data.get("baseSeverity")
                return {"description": desc, "published_date": cve_item.get("published"), "cvss_v3_score": score, "severity": severity}
        except Exception: pass
        return empty_info

    # ================= 2. GitHub 代码下载 =================
    def fetch_github_lines(self, github_url: str, commit_id: str, file_path: str) -> List[str]:
        if not isinstance(github_url, str): return []
        clean_url = github_url.rstrip("/").replace(".git", "")
        parts = clean_url.split("/")
        if len(parts) < 2: return []
        raw_url = f"https://raw.githubusercontent.com/{parts[-2]}/{parts[-1]}/{commit_id}/{file_path}"
        time.sleep(0.3)
        try:
            resp = self.session.get(raw_url, timeout=20)
            if resp.status_code == 200:
                return resp.text.splitlines(keepends=True)
        except: pass
        return []

    # ================= 3. 核心算法: 签名加权搜索 =================
    def _find_best_match_method(self, lines: List[str], method_name: str, signature: Optional[str], hint_line: int) -> int:
        """
        在 Buggy 文件中寻找最佳匹配的函数起始行。
        策略：
        1. 找出所有包含 method_name 的定义行。
        2. 如果有 signature，计算代码行与 signature 的关键词重合度 (Score)。
        3. 如果 Score 相同，或者没有 signature，取距离 hint_line 最近的那个。
        """
        candidates = [] # 存储 (line_index, line_content)
        
        # 1. 扫描所有可能的候选行
        for i, line in enumerate(lines):
            line = line.strip()
            # 初步过滤：必须包含方法名 + 左括号 + 不像是一行调用(以分号结尾且无大括号)
            if method_name in line and "(" in line:
                if ";" in line and "{" not in line:
                    continue # 忽略抽象方法或接口定义
                candidates.append(i)
        
        if not candidates:
            return -1 # 没找到任何匹配

        # 如果只有一个候选，直接返回
        if len(candidates) == 1:
            return candidates[0]

        # === 2. 签名评分算法 (Disambiguation Logic) ===
        best_candidate = -1
        best_score = -1
        min_distance = float('inf')

        # 预处理 signature token (如果有)
        sig_tokens = set()
        if signature:
            # 将 signature 拆分为单词集合，例如 "String retrieve(String, int)" -> {String, retrieve, int}
            sig_tokens = set(re.split(r'\W+', signature))
            sig_tokens.discard('') # 移除空串

        for idx in candidates:
            line_content = lines[idx]
            current_score = 0
            
            # 计算评分：代码行中有多少个单词出现在了 signature 里
            if signature:
                line_tokens = set(re.split(r'\W+', line_content))
                # 交集的大小即为得分
                current_score = len(sig_tokens.intersection(line_tokens))
            
            # 计算距离：离 CSV 给的行号有多远
            distance = abs(idx - hint_line)

            # === 决策逻辑 ===
            # 优先选 Score 高的 (匹配度高)
            if current_score > best_score:
                best_score = current_score
                min_distance = distance
                best_candidate = idx
            
            # 如果 Score 一样 (比如没有 signature，或者都匹配得很好)，选距离最近的
            elif current_score == best_score:
                if distance < min_distance:
                    min_distance = distance
                    best_candidate = idx
        
        return best_candidate

    def extract_code_snippets(self, project_slug: str, github_url: str, buggy_commit: str) -> List[Dict]:
        snippets = []
        fixes = self.df_fix[self.df_fix['project_slug'] == project_slug]
        
        if fixes.empty: return snippets

        for idx, row_fix in fixes.iterrows():
            if pd.isna(row_fix['file']): continue
            file_path = row_fix['file']
            
            method_name = row_fix['method']
            if pd.isna(method_name): method_name = "unknown"

            # 处理 NaN
            class_name = row_fix.get('class')
            if pd.isna(class_name): class_name = Path(file_path).stem 
            else: class_name = str(class_name).strip()

            raw_sig = row_fix.get('signature')
            if pd.isna(raw_sig): signature = None 
            else: signature = str(raw_sig).strip()

            try:
                hint_start = int(row_fix['method_start'])
                csv_end = int(row_fix['method_end'])
            except: 
                hint_start = 0; csv_end = 0

            # 1. 下载 Buggy 代码
            lines = self.fetch_github_lines(github_url, buggy_commit, file_path)
            
            base_info = {
                "file_path": file_path,
                "class_name": class_name,
                "method_name": method_name,
                "signature": signature,
                "lines_hint_csv": [hint_start, csv_end],
            }

            if not lines:
                base_info.update({"code": "", "is_missing_in_buggy_version": True, "status": "FILE_MISSING"})
                snippets.append(base_info)
                continue

            # 2. 【核心】使用新的加权搜索算法
            # hint_start 是 1-based，转 0-based
            found_idx = self._find_best_match_method(lines, method_name, signature, hint_start - 1)

            if found_idx == -1:
                base_info.update({"code": "", "is_missing_in_buggy_version": True, "status": "METHOD_MISSING"})
                snippets.append(base_info)
                continue

            # 3. 向下寻找平衡的大括号 (完整提取)
            real_start_idx = found_idx
            real_end_idx = real_start_idx
            balance = 0
            found_brace = False
            
            for i in range(real_start_idx, len(lines)):
                line = lines[i]
                opens = line.count('{')
                closes = line.count('}')
                if opens > 0: found_brace = True
                balance += (opens - closes)
                real_end_idx = i
                if found_brace and balance == 0:
                    break
            
            e_idx = real_end_idx + 1
            code_str = "".join(lines[real_start_idx:e_idx])

            # 4. 组装结果
            if not code_str.strip():
                base_info.update({"code": "", "is_missing_in_buggy_version": True, "status": "EMPTY_BODY"})
            else:
                base_info.update({
                    "code": code_str,
                    "is_missing_in_buggy_version": False,
                    "status": "FOUND",
                    "lines_extracted": [real_start_idx + 1, e_idx]
                })
            snippets.append(base_info)
            
        return snippets

    # ================= 4. 数据生成与保存 =================
    def generate_single_cve_data(self, row_project) -> Optional[Dict]:
        cve_id = row_project['cve_id']
        project_slug = row_project['project_slug']
        nvd_info = self.fetch_nvd_info(cve_id)
        snippets = self.extract_code_snippets(project_slug, row_project['github_url'], row_project['buggy_commit_id'])
        
        if not snippets and nvd_info['description'] == "N/A": return None

        return {
            "cve_id": cve_id,
            "project_slug": project_slug,
            "buggy_commit_id": row_project['buggy_commit_id'],
            "github_url": row_project['github_url'],
            "nvd_metadata": nvd_info,
            "code_snippets": snippets
        }

    def run_interactive(self):
        print("\n--- 单个查询模式 ---")
        while True:
            cve = input("\n请输入 CVE 号 (q 退出): ").strip().upper()
            if cve == 'Q': break
            projs = self.df_project[self.df_project['cve_id'] == cve]
            if projs.empty: print("❌ 未找到"); continue
            data = self.generate_single_cve_data(projs.iloc[0])
            if data:
                p = self.output_dir / f"debug_{cve}.json"
                with open(p, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"✅ 保存: {p}")
            else: print("⚠️ 无数据")

    def run_batch(self):
        total = len(self.df_project)
        print(f"\n--- 批量处理 (Signature Enhanced) ---")
        print(f"结果存入: {self.combined_file_path}")
        if input("确认开始? (y/n): ").lower() != 'y': return

        all_data = []
        processed = set()
        if self.combined_file_path.exists():
            try:
                with open(self.combined_file_path, "r", encoding="utf-8") as f:
                    all_data = json.load(f)
                    processed = {x['cve_id'] for x in all_data}
                print(f"加载历史: {len(all_data)}")
            except: pass

        cnt = 0
        for idx, row in self.df_project.iterrows():
            cid = row['cve_id']
            if cid in processed:
                print(f"[{idx+1}/{total}] {cid} 跳过")
                continue
            print(f"[{idx+1}/{total}] {cid} ", end="")
            try:
                d = self.generate_single_cve_data(row)
                if d:
                    all_data.append(d)
                    processed.add(cid)
                    cnt += 1
                    print("✅")
                else: print("⚠️")
                if cnt > 0 and cnt % 5 == 0:
                    with open(self.combined_file_path, "w", encoding="utf-8") as f:
                        json.dump(all_data, f, indent=2, ensure_ascii=False)
            except Exception as e: print(f"❌ {e}")
        
        with open(self.combined_file_path, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
        print("完成!")

if __name__ == "__main__":
    # === 使用统一配置模块 ===
    try:
        from config import get_repo_root, get_nvd_api_key
    except ImportError:
        # 如果 config.py 不存在，使用自动检测
        import os
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        if os.path.exists(os.path.join(parent_dir, "data", "project_info.csv")):
            REPO_ROOT = parent_dir
        else:
            REPO_ROOT = None
        MY_API_KEY = None
    else:
        REPO_ROOT = get_repo_root()
        MY_API_KEY = get_nvd_api_key()
    
    if not REPO_ROOT or not os.path.exists(REPO_ROOT):
        print(f"❌ 路径不存在或未配置: {REPO_ROOT}")
        print("\n请使用以下方式之一配置项目根路径：")
        print("  1. 设置环境变量: CWE_BENCH_JAVA_ROOT")
        print("  2. 创建 tools/config.json 文件，设置 repo_root")
        print("  3. 运行 python tools/config.py 创建配置模板")
        exit(1)
    
    miner = IntegratedVulnMiner(REPO_ROOT, MY_API_KEY)
    c = input("\n1.单查 / 2.批量: ")
    if c=='1': miner.run_interactive()
    elif c=='2': miner.run_batch()