import requests
import json
import os
import re

def debug_flag_issue():
    base_url = "http://127.0.0.1:5000/b9af31f66147e/"
    
    # 检查文件是否存在
    print("=== 文件状态检查 ===")
    files_to_check = ['flag.log', 'blockchain.log', 'blockchain.privkey']
    for file in files_to_check:
        if os.path.exists(file):
            print(f"✅ {file} 存在")
            try:
                with open(file, 'rb') as f:
                    content = f.read()
                    print(f"  大小: {len(content)} 字节")
                    if file.endswith('.log') and content:
                        print(f"  内容预览: {content[:200]}")
            except Exception as e:
                print(f"  读取错误: {e}")
        else:
            print(f"❌ {file} 不存在")
    
    # 检查当前session状态
    print("\n=== Session状态检查 ===")
    session = requests.Session()
    response = session.get(base_url)
    
    if 'Set-Cookie' in response.headers:
        print("✅ Session Cookie 正常")
    else:
        print("❌ 无法获取Session")
    
    # 检查flag端点
    print("\n=== Flag端点测试 ===")
    flag_response = session.get(base_url + "flag")
    print(f"Flag响应: {flag_response.text}")
    
    # 检查是否有钻石
    if "diamonds" in flag_response.text:
        diamonds_match = re.search(r'You have (\d+) diamonds', flag_response.text)
        if diamonds_match:
            diamonds = int(diamonds_match.group(1))
            print(f"当前钻石数量: {diamonds}")
    
    # 检查区块链状态
    print("\n=== 区块链状态检查 ===")
    response = session.get(base_url)
    if "genesis_block_hash" in response.text:
        genesis_match = re.search(r'hash of genesis block: ([a-f0-9]+)', response.text)
        if genesis_match:
            print(f"创世区块哈希: {genesis_match.group(1)}")
    
    # 尝试手动触发flag
    print("\n=== 手动触发Flag测试 ===")
    # 模拟有2个钻石的情况（如果当前没有）
    if "0 diamonds" in flag_response.text:
        print("需要先获得2个钻石...")
        # 这里可以添加获得钻石的代码

# 运行调试
debug_flag_issue()