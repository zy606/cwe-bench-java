import requests
import time
import json
import logging
import pandas as pd
from typing import Dict, Optional
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ================= 配置日志系统 =================
# 设置日志级别为 INFO，并在每条日志前加上时间戳，方便排查网络超时或报错发生的时间
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NVDFetcher:
    """
    NVD 数据抓取器类
    封装了网络请求、错误重试、速率限制控制和数据保存逻辑。
    """
    # NVD API v2.0 的官方接口地址
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        """
        初始化抓取器
        :param api_key: NVD 的 API Key（可选）。如果有 Key，请求速度更快。
        """
        # 伪装 User-Agent，防止被 NVD 服务器识别为脚本而拦截
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        
        # --- 核心网络优化：持久会话 + 底层重试机制 ---
        # 使用 Session 对象可以复用 TCP 连接（Keep-Alive），显著提高请求速度和稳定性
        self.session = requests.Session()
        
        # 配置重试策略 (应对服务器不稳定的情况)
        # total=5: 如果失败，最多自动在底层重试 5 次
        # backoff_factor=1: 重试等待时间指数增长 (第1次等1s, 第2次等2s, 第3次等4s...)
        # status_forcelist: 如果服务器返回 500/502/503/504 等服务器端错误，自动重试
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        
        # 将重试策略挂载到 https 协议上
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        # --- 速率限制配置 ---
        if api_key:
            self.headers["apiKey"] = api_key
            # 官方规则：有 Key 每30秒50次 (平均0.6秒/次)
            # 实际设置：为了防止网络波动导致封禁，设置为 1.5 秒/次，求稳
            self.delay = 1 
            logger.info("API Key 已配置 (延迟设置为 1.5s 以保证稳定)")
        else:
            # 官方规则：无 Key 每30秒5次 (平均6.0秒/次)
            self.delay = 6.0
            logger.warning("未配置 API Key (延迟 6.0s)")

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        查询单个 CVE 的详细信息（包含多层容错机制）
        :param cve_id: 例如 "CVE-2016-10726"
        :return: 包含漏洞信息的字典，如果失败返回 None
        """
        # 数据清洗：去除空格并转大写
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
             logger.error("格式错误：请输入正确的 CVE 号 (例如 CVE-2021-44228)")
             return None

        params = {"cveId": cve_id}
        
        # --- 应用层重试循环 ---
        # 针对 Session 无法自动处理的错误（如 SSL握手失败、403封禁、429限流）进行手动处理
        max_attempts = 5
        
        for attempt in range(max_attempts):
            try:
                # 每次请求前强制等待，严格遵守速率限制
                time.sleep(self.delay)
                
                # 发送请求 (超时时间设置为 60秒，防止网络慢导致断开)
                response = self.session.get(
                    self.BASE_URL, 
                    headers=self.headers, 
                    params=params, 
                    timeout=60 
                )

                # 1. 请求成功
                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        # 提取核心数据（vulnerabilities 列表中的第一个元素）
                        return vulns[0].get("cve", {})
                    else:
                        logger.warning(f"NVD 数据库中未找到 {cve_id}")
                        return None
                
                # 2. 处理 403 Forbidden (通常是 API Key 问题或 IP 暂时封禁)
                elif response.status_code == 403:
                    logger.warning("403 Forbidden - 可能 API Key 问题或 IP 被暂时封锁，等待 20秒...")
                    time.sleep(20)
                
                # 3. 处理 429 Too Many Requests (请求速度过快)
                elif response.status_code == 429:
                    logger.warning("429 Too Many Requests - 速度太快，等待 30秒...")
                    time.sleep(30)
                
                # 4. 其他错误
                else:
                    logger.error(f"请求失败 (Code: {response.status_code})")

            # --- 异常捕获 ---
            except requests.exceptions.SSLError as e:
                # SSL 错误常见于国内网络环境或 VPN 不稳定
                wait_time = (attempt + 1) * 5
                logger.warning(f"SSL 错误 (网络波动): {e} - 等待 {wait_time}秒后重试...")
                time.sleep(wait_time)
                
            except requests.exceptions.ConnectionError as e:
                # 连接直接被切断
                wait_time = (attempt + 1) * 5
                logger.warning(f"连接中断: {e} - 等待 {wait_time}秒后重试...")
                time.sleep(wait_time)
                
            except Exception as e:
                logger.error(f"未知错误: {e}")
                time.sleep(5)
        
        # 如果循环结束还没成功
        logger.error(f"【失败】{cve_id} 经过 {max_attempts} 次尝试后仍然失败。")
        return None

    def flatten_cve_data(self, cve_json: Dict) -> Dict:
        """
        辅助函数：将复杂的嵌套 JSON 数据扁平化，提取关键字段以便保存为 CSV 表格。
        """
        # 1. 提取描述（通常取英文描述）
        desc = "No description available"
        for d in cve_json.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break
        
        # 2. 提取 CVSS v3.1 评分和严重程度
        metrics = cve_json.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [])
        score = None
        severity = None
        if cvss_data:
            score = cvss_data[0].get("cvssData", {}).get("baseScore")
            severity = cvss_data[0].get("cvssData", {}).get("baseSeverity")

        # 返回简化后的字典
        return {
            "cve_id": cve_json.get("id"),
            "description": desc,
            "cvss_v3_score": score,
            "severity": severity,
            "published": cve_json.get("published"),
            "last_modified": cve_json.get("lastModified")
        }

    def save_single_cve(self, cve_data: Dict, output_dir: str):
        """保存单个查询结果到 JSON 文件"""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        cve_id = cve_data.get("id")
        
        json_path = out_path / f"{cve_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(cve_data, f, indent=4)
        
        logger.info(f"结果已保存至: {json_path}")

    def process_dataset(self, csv_path: str, output_dir: str):
        """
        批量处理函数：读取 input CSV，批量下载所有 CVE。
        具备【断点续传】功能。
        """
        csv_file = Path(csv_path)
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        if not csv_file.exists():
            logger.error(f"错误：找不到输入文件 {csv_path}")
            return

        # 读取 Pandas DataFrame
        df = pd.read_csv(csv_file)
        cve_ids = df['cve_id'].unique() # 去重
        logger.info(f"开始批量处理 {len(cve_ids)} 个 CVE...")

        for idx, cve_id in enumerate(cve_ids):
            json_file = out_path / f"{cve_id}.json"
            
            # --- 断点续传逻辑 ---
            # 如果文件已经存在，且大小大于0（不是空文件），则跳过下载
            if json_file.exists() and json_file.stat().st_size > 0:
                # logger.info(f"跳过已存在: {cve_id}")
                continue 

            logger.info(f"[{idx+1}/{len(cve_ids)}] 正在获取 {cve_id}...")
            data = self.get_cve_details(cve_id)
            
            if data:
                # 下载成功立即保存
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
            
            # 每下载 10 个 CVE，自动触发一次汇总（防止程序中途崩溃没有任何汇总数据）
            if (idx + 1) % 10 == 0:
                self.merge_results(out_path)

        # 循环结束后，执行最后一次完全汇总
        self.merge_results(out_path)

    def merge_results(self, output_dir: Path):
        """
        汇总函数：扫描文件夹下所有 .json 文件，合并成一个大的 CSV 和 JSON。
        此函数可单独离线运行。
        """
        all_csv_rows = []
        all_json_data = [] 
        
        # 遍历目录下所有以 CVE- 开头的 JSON 文件
        for f in output_dir.glob("CVE-*.json"):
            try:
                with open(f, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                    all_json_data.append(data)
                    # 扁平化数据以存入 CSV
                    all_csv_rows.append(self.flatten_cve_data(data))
            except: 
                continue # 如果某个文件损坏，跳过它

        if all_csv_rows:
            # 导出为 CSV (Excel 可打开)
            df = pd.DataFrame(all_csv_rows)
            df.to_csv(output_dir / "all_cves_combined.csv", index=False, encoding="utf_8_sig")
            
            # 导出为 JSON (完整数据)
            with open(output_dir / "all_cves_combined.json", "w", encoding="utf-8") as f:
                json.dump(all_json_data, f, indent=4)

# ================= 主程序入口 =================
if __name__ == "__main__":
    # --- 用户配置区域 (请修改这里) ---
    # 1. 你的 API Key
    MY_API_KEY = "fb382a79-0bec-425e-b449-e0258468588f"
    
    # 2. 你的本地 CSV 路径 (使用 r"" 防止反斜杠转义)
    LOCAL_CSV_PATH = r"D:\克隆仓库\cwe-bench-java\data\project_info.csv"
    
    # 3. 结果保存文件夹名称
    SAVE_DIR = "nvd_results"

    # 初始化抓取器
    fetcher = NVDFetcher(api_key=MY_API_KEY)

    # 交互式菜单
    while True:
        print("\n" + "="*40)
        print("          NVD 数据抓取工具 ")
        print("="*40)
        print("1. [单次] 输入 CVE 号查询")
        print("2. [批量] 处理 cwe-bench-java 数据集")
        print("3. [汇总] 仅运行合并数据 (生成CSV)")
        print("q. 退出程序")
        print("-" * 40)
        
        choice = input("请输入选项 (1/2/3/q): ").strip().lower()

        if choice == '1':
            target = input("\n请输入 CVE 号 (例如 CVE-2016-10726): ").strip()
            if target:
                print(f"正在查询 {target} ...")
                result = fetcher.get_cve_details(target)
                if result:
                    print(f"\n[成功] 描述: {result.get('descriptions')[0].get('value')[:100]}...")
                    fetcher.save_single_cve(result, SAVE_DIR)
                else:
                    print("\n[失败] 未获取到数据或达到重试上限。")
        
        elif choice == '2':
            print("\n准备开始批量处理...")
            print("注意：如果遇到 SSL/Connection 报错，程序会自动等待并重试，请耐心等待。")
            fetcher.process_dataset(LOCAL_CSV_PATH, SAVE_DIR)
            print("\n批量处理结束。")

        elif choice == '3':
            print("\n正在扫描 nvd_results 目录并生成汇总 CSV...")
            fetcher.merge_results(Path(SAVE_DIR))
            print("完成。")
        
        elif choice == 'q':
            print("退出程序。")
            break
        
        else:
            print("无效输入，请重新选择。")