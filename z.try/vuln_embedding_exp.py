import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# ================= 配置区域 =================
# 推荐使用专门针对代码优化的模型
MODEL_NAME = "jinaai/jina-embeddings-v2-base-code"
# 输出文件夹名称
OUTPUT_FOLDER = "output"
# ===========================================

def main():
    # 1. 确定输出路径 (相对于当前脚本所在的目录)
    current_script_path = Path(__file__).resolve()
    script_dir = current_script_path.parent
    output_dir = script_dir / OUTPUT_FOLDER
    
    # 创建输出目录
    output_dir.mkdir(exist_ok=True)
    
    print(f"🚀 正在初始化...")
    print(f"📂 结果将输出至: {output_dir}")

    # 2. 加载模型
    print(f"⏳ 正在加载模型: {MODEL_NAME} ...")
    try:
        model = SentenceTransformer(MODEL_NAME, trust_remote_code=True)
        print("✅ 模型加载成功！")
    except Exception as e:
        print(f"❌ 模型加载失败: {e}")
        print("建议检查网络或尝试: pip install sentence-transformers")
        sys.exit(1)

    # 3. 准备 10 个样本对 (自然语言描述 NL vs 代码 Code)
    # 使用英文标签以确保在文本文件中完美对齐
    labels = [
        "SQL_Injection", "XSS", "Path_Traversal", "Auth_Bypass", "Bubble_Sort",
        "Cmd_Injection", "Deserialization", "XXE", "Weak_Crypto", "Hardcoded_Creds"
    ]

    nl_descriptions = [
        "SQL injection vulnerability where user input is concatenated directly into a database query string.",
        "Cross-site scripting (XSS) vulnerability allowing injection of malicious scripts into web pages.",
        "Path traversal vulnerability allowing access to files outside the web root directory.",
        "Authentication bypass due to improper validation of user tokens or credentials.",
        "Bubble sort algorithm implementation for sorting an array of integers.",
        "Command injection vulnerability where user input is executed as an operating system command.",
        "Insecure deserialization vulnerability allowing arbitrary code execution when untrusted data is deserialized.",
        "XML External Entity (XXE) processing vulnerability allowing disclosure of confidential data.",
        "Use of weak cryptographic algorithm (MD5) for hashing passwords, susceptible to collision.",
        "Hardcoded credentials in source code allowing unauthorized access to the system."
    ]

    code_samples = [
        # 1. SQL Injection
        """public User getUser(String user) { String q = "SELECT * FROM users WHERE u = '" + user + "'"; return db.exec(q); }""",
        # 2. XSS
        """public void doGet(Req req, Resp resp) { String input = req.getParam("in"); resp.getWriter().write(input); }""",
        # 3. Path Traversal
        """public File getFile(String fn) { return new File("/var/www/uploads/" + fn); }""",
        # 4. Auth Bypass
        """public boolean check(String t) { if (t.equals("admin_debug")) return true; return validate(t); }""",
        # 5. Bubble Sort
        """void sort(int a[]) { for(int i=0;i<n;i++) for(int j=0;j<n-i-1;j++) if(a[j]>a[j+1]) swap(a,j,j+1); }""",
        # 6. Command Injection
        """public void run(String cmd) { Runtime.getRuntime().exec("ping " + cmd); }""",
        # 7. Insecure Deserialization
        """public Object read(Stream in) { return new ObjectInputStream(in).readObject(); }""",
        # 8. XXE
        """DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setExpandEntityReferences(true); dbf.newDocumentBuilder().parse(f);""",
        # 9. Weak Crypto
        """MessageDigest md = MessageDigest.getInstance("MD5"); md.update(p.getBytes());""",
        # 10. Hardcoded Credentials
        """if (user.equals("admin") && pass.equals("123456")) { login(); }"""
    ]

    # 4. 计算 Embeddings
    print("⏳ 正在生成向量 (Embeddings)...")
    nl_embeddings = model.encode(nl_descriptions)
    code_embeddings = model.encode(code_samples)

    # 5. 定义计算并保存矩阵的函数
    def process_matrix(emb1, emb2, name_row, name_col, file_name, title):
        # 计算相似度
        sim_matrix = cosine_similarity(emb1, emb2)
        # 转为 DataFrame
        df = pd.DataFrame(sim_matrix, index=name_row, columns=name_col)
        
        # 1. 保存 CSV (用于数据分析)
        csv_path = output_dir / f"{file_name}.csv"
        df.to_csv(csv_path)
        
        # 2. 返回格式化后的字符串 (用于人类阅读)
        # 设置显示精度为2位小数，列宽自适应
        formatted_str = f"\n{'='*20} {title} {'='*20}\n\n"
        formatted_str += df.to_string(float_format=lambda x: "{:.4f}".format(x))
        formatted_str += "\n\n"
        return formatted_str

    # 6. 执行三个实验
    print("📊 正在计算相似度矩阵...")
    
    report_content = "Vulnerability Embedding Similarity Report\n"
    report_content += f"Model: {MODEL_NAME}\n"
    report_content += "="*60 + "\n"

    # 实验 1: NL vs NL
    report_content += process_matrix(nl_embeddings, nl_embeddings, labels, labels, 
                                   "nl_nl_similarity", "Experiment 1: NL vs NL Similarity")

    # 实验 2: Code vs Code
    report_content += process_matrix(code_embeddings, code_embeddings, labels, labels, 
                                   "code_code_similarity", "Experiment 2: Code vs Code Similarity")

    # 实验 3: NL vs Code (最关键的实验)
    report_content += process_matrix(nl_embeddings, code_embeddings, labels, labels, 
                                   "nl_code_similarity", "Experiment 3: NL (Rows) vs Code (Cols) Similarity")

    # 7. 保存可视化报告
    report_path = output_dir / "similarity_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print("\n" + "="*50)
    print("✅ 执行完成！输出文件如下：")
    print(f"1. 数据文件 (CSV): {output_dir}")
    print(f"2. 可视化报告 (TXT): {report_path}  <-- 请打开此文件查看矩阵")
    print("="*50)

    # 8. 在控制台预览 NL-Code 的对角线结果 (Matching Pairs)
    print("\n🔍 预览: 匹配对(NL-Code)的相似度得分:")
    nl_code_df = pd.read_csv(output_dir / "nl_code_similarity.csv", index_col=0)
    for label in labels:
        score = nl_code_df.loc[label, label]
        print(f"  - {label:<15} : {score:.4f}")

if __name__ == "__main__":
    main()