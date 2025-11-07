import requests
import json

# 你的URL前缀
prefix = "b9af31f66147e"  # 替换为你的有效前缀
url = f"http://127.0.0.1:5000/{prefix}/create_transaction"

# 构造区块数据
block_data = {
    "prev": "d0134a3f7e90745e98ed0be5bd69a7eb28241fdedbe57f3b65cd5cd021494d98",
    "nonce": "你的nonce值", 
    "transactions": [
        # 你的交易数据
    ]
}

# 发送POST请求
response = requests.post(url, json=block_data)

# 直接打印响应内容 - 这里就会显示错误信息
print("服务器响应:", response.text)