import os
os.environ["http_proxy"] = "http://127.0.0.1:7897"
os.environ["https_proxy"] = "http://127.0.0.1:7897"
import google.generativeai as genai

# 填入你的 Key
API_KEY = "AIzaSyBWtDjtTNHAeqxqvD_suvjym3Te9cxH48I"
genai.configure(api_key=API_KEY)

print("--- 可用的 Gemini 模型列表 ---")
for m in genai.list_models():
    # 我们只关心支持 'generateContent' 方法的模型 (也就是对话模型)
    if 'generateContent' in m.supported_generation_methods:
        print(f"Name: {m.name}")
        print(f"Display Name: {m.display_name}")
        print("-" * 20)