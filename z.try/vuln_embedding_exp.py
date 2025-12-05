import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import sys
import traceback
import os
from pathlib import Path
from datetime import datetime

# 1. 加载模型（直接使用 v2）
print("正在加载 Jina Embeddings v2 模型...")
print("注意：首次运行需要下载模型，可能需要几分钟时间...")

try:
    model = SentenceTransformer("jinaai/jina-embeddings-v2-base-en")
    model_name = "jinaai/jina-embeddings-v2-base-en"
    print("✓ v2 模型加载完成！")
except Exception as e:
    print(f"✗ 模型加载失败: {e}")
    print("\n故障排除建议：")
    print("1. 检查网络连接（首次运行需要下载模型）")
    print("2. 清理 HuggingFace 缓存：")
    print("   - Windows: 删除 C:\\Users\\<用户名>\\.cache\\huggingface\\")
    print("3. 检查是否有足够的磁盘空间")
    raise

# 2. 准备样本数据
# 精选5个自然语言描述和5个漏洞代码样本，确保良好的对比效果

# ========== 自然语言描述样本（5个）==========
# 1. SQL 注入描述
desc_sqli = "SQL injection vulnerability occurs when user input is directly concatenated into SQL query strings without sanitization, allowing attackers to execute arbitrary SQL commands."

# 2. XSS 漏洞描述
desc_xss = "Cross-site scripting (XSS) vulnerability occurs when user input is rendered in HTML without proper encoding, allowing attackers to inject malicious JavaScript code into web pages."

# 3. 路径遍历描述
desc_path_traversal = "Path traversal vulnerability occurs when file paths are constructed using unsanitized user input, allowing attackers to access arbitrary files outside the intended directory using sequences like '../'."

# 4. 认证绕过描述
desc_auth_bypass = "Authentication bypass vulnerability occurs when the application fails to properly validate authentication tokens, allowing unauthorized users to access protected resources."

# 5. 排序算法描述（完全无关，用于对比）
desc_sort = "Bubble sort is a simple sorting algorithm that repeatedly steps through the list, compares adjacent elements and swaps them if they are in the wrong order."

# ========== 漏洞代码样本（5个）==========
# 1. SQL 注入漏洞代码 (Java)
code_sqli = """
public User getUser(String username) {
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    return parseUser(rs);
}
"""

# 2. XSS 漏洞代码 (Java Servlet)
code_xss = """
public void doGet(HttpServletRequest request, HttpServletResponse response) {
    String userComment = request.getParameter("comment");
    response.getWriter().println("<div class='comment'>" + userComment + "</div>");
}
"""

# 3. 路径遍历漏洞代码 (Java)
code_path_traversal = """
public void downloadFile(HttpServletRequest request, HttpServletResponse response) {
    String filename = request.getParameter("file");
    File file = new File("/var/www/uploads/" + filename);
    Files.copy(file.toPath(), response.getOutputStream());
}
"""

# 4. 认证绕过漏洞代码
code_auth_bypass = """
public boolean isAuthenticated(String token) {
    if (token != null && token.length() > 0) {
        return true;  // Missing actual token validation
    }
    return false;
}
"""

# 5. 排序算法代码 (Python) - 完全无关，用于对比
code_sort = """
def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
    return arr
"""

# ---------------------------------------------------------
# 辅助函数：计算余弦相似度
def calc_sim(vec1, vec2):
    # reshape(1, -1) 是为了符合 sklearn 的输入格式
    return cosine_similarity(vec1.reshape(1, -1), vec2.reshape(1, -1))[0][0]

# 准备输出目录
output_dir = Path(__file__).parent / "output"
output_dir.mkdir(exist_ok=True)
output_file = output_dir / "result.txt"

# 用于收集所有输出内容
output_lines = []

def log_print(*args, **kwargs):
    """同时打印到控制台和保存到输出列表"""
    line = ' '.join(str(arg) for arg in args)
    print(*args, **kwargs)
    output_lines.append(line)

print("\n---------------- 实验开始 ----------------")
log_print("\n" + "="*60)
log_print("Embedding 相似度分析实验")
log_print("="*60)
log_print(f"模型: {model_name}")
log_print(f"实验时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log_print("="*60)

# 准备所有自然语言描述（5个）
nl_descriptions = {
    "SQL注入": desc_sqli,
    "XSS漏洞": desc_xss,
    "路径遍历": desc_path_traversal,
    "认证绕过": desc_auth_bypass,
    "排序算法": desc_sort,
}

# 准备所有代码样本（5个）
code_samples = {
    "SQL注入": code_sqli,
    "XSS漏洞": code_xss,
    "路径遍历": code_path_traversal,
    "认证绕过": code_auth_bypass,
    "排序算法": code_sort,
}

# ==========================================
# 实验 1: NL vs NL (自然语言相似度)
# ==========================================
log_print("\n" + "="*70)
log_print("[实验 1] 自然语言 vs 自然语言 (NL-NL)")
log_print("="*70)
log_print("  正在生成 embeddings...")

# 生成所有描述的 embeddings
log_print("  正在编码所有自然语言描述...")
nl_embeddings = {}
for name, desc in nl_descriptions.items():
    embedding = model.encode(desc, show_progress_bar=False)
    nl_embeddings[name] = embedding
    log_print(f"  {name}: embedding shape = {embedding.shape}, dtype = {embedding.dtype}")

log_print("  ✓ Embeddings 生成完成\n")

# 输出自然语言描述的 embeddings
log_print("自然语言描述 Embeddings:")
log_print("-" * 70)
nl_names = list(nl_descriptions.keys())

for name in nl_names:
    embedding = nl_embeddings[name]
    log_print(f"\n{name}:")
    log_print(f"  Shape: {embedding.shape}")
    log_print(f"  Dtype: {embedding.dtype}")
    log_print(f"  Min: {np.min(embedding):.6f}, Max: {np.max(embedding):.6f}, Mean: {np.mean(embedding):.6f}")
    log_print(f"  First 10 values: {embedding[:10]}")
    log_print(f"  Last 10 values: {embedding[-10:]}")

# 计算自然语言描述之间的相似度
log_print("\n" + "-"*70)
log_print("自然语言 vs 自然语言相似度 (NL-NL):")
log_print("-" * 70)

nl_similarity_matrix = {}
for i, name1 in enumerate(nl_names):
    for j, name2 in enumerate(nl_names):
        if i <= j:  # 包括对角线
            sim = calc_sim(nl_embeddings[name1], nl_embeddings[name2])
            pair_key = f"{name1} vs {name2}"
            nl_similarity_matrix[pair_key] = float(sim)
            if i < j:  # 非对角线才打印
                log_print(f"  {name1:15s} vs {name2:15s}: {sim:.4f}")


# ==========================================
# 实验 2: Code vs Code (代码相似度)
# ==========================================
log_print("\n" + "="*70)
log_print("[实验 2] 代码 vs 代码 (Code-Code)")
log_print("="*70)
log_print("  正在生成 embeddings...")

# 生成所有代码的 embeddings
log_print("  正在编码所有代码样本...")
code_embeddings = {}
for name, code in code_samples.items():
    embedding = model.encode(code, show_progress_bar=False)
    code_embeddings[name] = embedding
    log_print(f"  {name}: embedding shape = {embedding.shape}, dtype = {embedding.dtype}")

log_print("  ✓ Embeddings 生成完成\n")

# 输出代码的 embeddings
log_print("代码 Embeddings:")
log_print("-" * 70)
code_names = list(code_samples.keys())

for name in code_names:
    embedding = code_embeddings[name]
    log_print(f"\n{name}:")
    log_print(f"  Shape: {embedding.shape}")
    log_print(f"  Dtype: {embedding.dtype}")
    log_print(f"  Min: {np.min(embedding):.6f}, Max: {np.max(embedding):.6f}, Mean: {np.mean(embedding):.6f}")
    log_print(f"  First 10 values: {embedding[:10]}")
    log_print(f"  Last 10 values: {embedding[-10:]}")

# 计算代码之间的相似度
log_print("\n" + "-"*70)
log_print("代码 vs 代码相似度 (Code-Code):")
log_print("-" * 70)

code_similarity_matrix = {}
for i, name1 in enumerate(code_names):
    for j, name2 in enumerate(code_names):
        if i <= j:  # 包括对角线
            sim = calc_sim(code_embeddings[name1], code_embeddings[name2])
            pair_key = f"{name1} vs {name2}"
            code_similarity_matrix[pair_key] = float(sim)
            if i < j:  # 非对角线才打印
                log_print(f"  {name1:15s} vs {name2:15s}: {sim:.4f}")


# ==========================================
# 实验 3: NL vs Code (跨模态检索)
# ==========================================
log_print("\n" + "="*70)
log_print("[实验 3] 自然语言 vs 代码 Embeddings 对比")
log_print("="*70)
log_print("  展示自然语言描述和代码的 embedding 信息\n")

# 输出自然语言和代码的 embedding 信息对比
log_print("自然语言和代码 Embeddings 对比:")
log_print("-" * 70)

security_vulns = ["SQL注入", "XSS漏洞", "路径遍历", "认证绕过"]
security_codes = ["SQL注入", "XSS漏洞", "路径遍历", "认证绕过"]

log_print("\n匹配对 - 描述与对应代码的 Embedding 信息:")
matching_pairs = [
    ("SQL注入", "SQL注入"),
    ("XSS漏洞", "XSS漏洞"),
    ("路径遍历", "路径遍历"),
    ("认证绕过", "认证绕过"),
    ("排序算法", "排序算法"),
]

nl_code_similarity_matrix = {}
for nl_name, code_name in matching_pairs:
    nl_emb = nl_embeddings[nl_name]
    code_emb = code_embeddings[code_name]
    sim = calc_sim(nl_emb, code_emb)
    pair_key = f"{nl_name} (NL) vs {code_name} (Code)"
    nl_code_similarity_matrix[pair_key] = float(sim)
    
    log_print(f"\n{nl_name} (NL) vs {code_name} (Code):")
    log_print(f"  相似度: {sim:.4f}")
    log_print(f"  NL Shape: {nl_emb.shape}, Code Shape: {code_emb.shape}")
    log_print(f"  NL Range: [{np.min(nl_emb):.6f}, {np.max(nl_emb):.6f}], Mean: {np.mean(nl_emb):.6f}")
    log_print(f"  Code Range: [{np.min(code_emb):.6f}, {np.max(code_emb):.6f}], Mean: {np.mean(code_emb):.6f}")
    log_print(f"  NL First 5: {nl_emb[:5]}")
    log_print(f"  Code First 5: {code_emb[:5]}")

# 计算所有自然语言和代码之间的相似度（完整矩阵）
log_print("\n" + "-"*70)
log_print("自然语言 vs 代码相似度矩阵 (NL-Code):")
log_print("-" * 70)

# 打印表头
log_print(f"{'NL\\Code':15s}", end="")
for code_name in code_names:
    log_print(f"{code_name:12s}", end="")
log_print("")  # 换行
log_print("-" * 70)

# 打印相似度矩阵
for nl_name in nl_names:
    log_print(f"{nl_name:15s}", end="")
    for code_name in code_names:
        sim = calc_sim(nl_embeddings[nl_name], code_embeddings[code_name])
        pair_key = f"{nl_name} vs {code_name}"
        if pair_key not in nl_code_similarity_matrix:
            nl_code_similarity_matrix[pair_key] = float(sim)
        log_print(f"{sim:12.4f}", end="")
    log_print("")  # 换行

# 创建子目录
embeddings_dir = output_dir / "embeddings"
similarity_dir = output_dir / "similarity"
embeddings_dir.mkdir(exist_ok=True)
similarity_dir.mkdir(exist_ok=True)

# ==========================================
# 保存 Embeddings 到 embeddings 目录
# ==========================================
log_print("\n" + "="*70)
log_print("保存 Embeddings 到 embeddings/ 目录")
log_print("="*70)

# 保存为 numpy 格式
nl_embeddings_file = embeddings_dir / "nl_embeddings.npy"
code_embeddings_file = embeddings_dir / "code_embeddings.npy"

# 将 embeddings 组织成字典格式保存
nl_embeddings_dict = {name: nl_embeddings[name] for name in nl_names}
code_embeddings_dict = {name: code_embeddings[name] for name in code_names}

# 保存为 numpy 文件
np.save(nl_embeddings_file, nl_embeddings_dict, allow_pickle=True)
np.save(code_embeddings_file, code_embeddings_dict, allow_pickle=True)

log_print(f"\n自然语言 Embeddings 已保存到: {nl_embeddings_file}")
log_print(f"代码 Embeddings 已保存到: {code_embeddings_file}")

# 保存 embedding 信息为文本文件（便于查看）
nl_embeddings_info_file = embeddings_dir / "nl_embeddings_info.txt"
with open(nl_embeddings_info_file, 'w', encoding='utf-8') as f:
    f.write("自然语言 Embeddings 信息\n")
    f.write("="*70 + "\n\n")
    for name in nl_names:
        emb = nl_embeddings[name]
        f.write(f"{name}:\n")
        f.write(f"  Shape: {emb.shape}\n")
        f.write(f"  Dtype: {emb.dtype}\n")
        f.write(f"  Min: {np.min(emb):.6f}, Max: {np.max(emb):.6f}, Mean: {np.mean(emb):.6f}\n")
        f.write(f"  First 10 values: {emb[:10]}\n")
        f.write(f"  Last 10 values: {emb[-10:]}\n\n")
log_print(f"自然语言 Embeddings 信息已保存到: {nl_embeddings_info_file}")

code_embeddings_info_file = embeddings_dir / "code_embeddings_info.txt"
with open(code_embeddings_info_file, 'w', encoding='utf-8') as f:
    f.write("代码 Embeddings 信息\n")
    f.write("="*70 + "\n\n")
    for name in code_names:
        emb = code_embeddings[name]
        f.write(f"{name}:\n")
        f.write(f"  Shape: {emb.shape}\n")
        f.write(f"  Dtype: {emb.dtype}\n")
        f.write(f"  Min: {np.min(emb):.6f}, Max: {np.max(emb):.6f}, Mean: {np.mean(emb):.6f}\n")
        f.write(f"  First 10 values: {emb[:10]}\n")
        f.write(f"  Last 10 values: {emb[-10:]}\n\n")
log_print(f"代码 Embeddings 信息已保存到: {code_embeddings_info_file}")

# ==========================================
# 保存相似度结果到 similarity 目录
# ==========================================
log_print("\n" + "="*70)
log_print("保存相似度结果到 similarity/ 目录")
log_print("="*70)

# 保存相似度结果到 JSON 文件
import json

similarity_results = {
    "nl_nl": nl_similarity_matrix,
    "code_code": code_similarity_matrix,
    "nl_code": nl_code_similarity_matrix,
}

similarity_file = similarity_dir / "similarity_results.json"
with open(similarity_file, 'w', encoding='utf-8') as f:
    json.dump(similarity_results, f, indent=2, ensure_ascii=False)

log_print(f"相似度结果 (JSON) 已保存到: {similarity_file}")

# 保存相似度矩阵为 CSV 格式（便于查看）
import csv

# NL-NL 相似度矩阵 CSV
nl_nl_csv = similarity_dir / "nl_nl_similarity.csv"
with open(nl_nl_csv, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow([''] + nl_names)
    for i, name1 in enumerate(nl_names):
        row = [name1]
        for j, name2 in enumerate(nl_names):
            sim = calc_sim(nl_embeddings[name1], nl_embeddings[name2])
            row.append(f"{sim:.4f}")
        writer.writerow(row)
log_print(f"NL-NL 相似度矩阵已保存到: {nl_nl_csv}")

# Code-Code 相似度矩阵 CSV
code_code_csv = similarity_dir / "code_code_similarity.csv"
with open(code_code_csv, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow([''] + code_names)
    for i, name1 in enumerate(code_names):
        row = [name1]
        for j, name2 in enumerate(code_names):
            sim = calc_sim(code_embeddings[name1], code_embeddings[name2])
            row.append(f"{sim:.4f}")
        writer.writerow(row)
log_print(f"Code-Code 相似度矩阵已保存到: {code_code_csv}")

# NL-Code 相似度矩阵 CSV
nl_code_csv = similarity_dir / "nl_code_similarity.csv"
with open(nl_code_csv, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['NL\\Code'] + code_names)
    for nl_name in nl_names:
        row = [nl_name]
        for code_name in code_names:
            sim = calc_sim(nl_embeddings[nl_name], code_embeddings[code_name])
            row.append(f"{sim:.4f}")
        writer.writerow(row)
log_print(f"NL-Code 相似度矩阵已保存到: {nl_code_csv}")

# 统计信息
log_print("\n" + "="*70)
log_print("Embedding 统计信息")
log_print("="*70)

log_print("\n自然语言 Embeddings:")
log_print(f"  - 样本数量: {len(nl_embeddings)}")
log_print(f"  - Embedding 维度: {list(nl_embeddings.values())[0].shape[0]}")
for name, emb in nl_embeddings.items():
    log_print(f"  - {name}: shape={emb.shape}, range=[{np.min(emb):.6f}, {np.max(emb):.6f}], mean={np.mean(emb):.6f}")

log_print("\n代码 Embeddings:")
log_print(f"  - 样本数量: {len(code_embeddings)}")
log_print(f"  - Embedding 维度: {list(code_embeddings.values())[0].shape[0]}")
for name, emb in code_embeddings.items():
    log_print(f"  - {name}: shape={emb.shape}, range=[{np.min(emb):.6f}, {np.max(emb):.6f}], mean={np.mean(emb):.6f}")

log_print(f"\n所有结果已保存到: {output_dir}")
log_print(f"\n文件结构:")
log_print(f"  {output_dir}/")
log_print(f"    ├── result.txt                    # 完整实验报告")
log_print(f"    ├── embeddings/                  # Embedding 信息目录")
log_print(f"    │   ├── nl_embeddings.npy        # 自然语言 embeddings (numpy)")
log_print(f"    │   ├── code_embeddings.npy      # 代码 embeddings (numpy)")
log_print(f"    │   ├── nl_embeddings_info.txt   # 自然语言 embeddings 信息")
log_print(f"    │   └── code_embeddings_info.txt # 代码 embeddings 信息")
log_print(f"    └── similarity/                  # 相似度信息目录")
log_print(f"        ├── similarity_results.json  # 所有相似度结果 (JSON)")
log_print(f"        ├── nl_nl_similarity.csv     # NL-NL 相似度矩阵 (CSV)")
log_print(f"        ├── code_code_similarity.csv # Code-Code 相似度矩阵 (CSV)")
log_print(f"        └── nl_code_similarity.csv   # NL-Code 相似度矩阵 (CSV)")

# 保存结果到文件
with open(output_file, 'w', encoding='utf-8') as f:
    f.write('\n'.join(output_lines))

print(f"\n✓ 结果已保存到: {output_file}")