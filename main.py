import requests
import time
import json
import random
from datetime import datetime, timezone, timedelta

# --- 配置 ---
# 建议将凭据存储在环境变量或配置文件中，而不是硬编码在脚本里
EMAIL = "zhuyiheai@gmail.com"
PASSWORD = "y399v8uql1"

BASE_URL = "https://servercreationlemon.onrender.com"
LOGIN_URL = f"{BASE_URL}/auth/login"
ME_URL = f"{BASE_URL}/auth/me"
AFK_URL = f"{BASE_URL}/credits/afk"

# 积分控制配置
CREDITS_TARGET_MIN = 110
CREDITS_TARGET_MAX = 130
CREDITS_MONTHLY_TARGET = None  # 每月初会随机生成

# 通用请求头，可以根据需要调整
HEADERS = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'origin': 'https://dash.lemonhost.me',
    'pragma': 'no-cache',
    'referer': 'https://dash.lemonhost.me/',
    'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'
}

def login():
    """执行登录请求并返回token"""
    print("正在尝试登录...")
    payload = {
        "email": EMAIL,
        "password": PASSWORD
    }
    try:
        response = requests.post(LOGIN_URL, headers=HEADERS, json=payload, timeout=10)
        response.raise_for_status()  # 如果请求失败则抛出HTTPError
        data = response.json()
        token = data.get("token")
        if not token:
            print("登录失败：未在响应中找到token。")
            return None
        print("登录成功！")
        return token
    except requests.exceptions.RequestException as e:
        print(f"登录请求失败：{e}")
        return None

def get_user_info(token):
    """获取用户信息"""
    print("正在获取用户信息...")
    auth_headers = HEADERS.copy()
    auth_headers['authorization'] = f'Bearer {token}'
    try:
        response = requests.get(ME_URL, headers=auth_headers, timeout=10)
        response.raise_for_status()
        user_data = response.json().get("user")
        if not user_data:
            print("获取用户信息失败：响应中没有'user'字段。")
            return None
        print("成功获取用户信息。")
        return user_data
    except requests.exceptions.RequestException as e:
        print(f"获取用户信息请求失败：{e}")
        return None

def send_afk_heartbeat(token):
    """发送AFK心跳请求"""
    print("正在发送AFK心跳请求...")
    auth_headers = HEADERS.copy()
    auth_headers['authorization'] = f'Bearer {token}'
    # POST请求，但没有body，所以使用data=None
    try:
        response = requests.post(AFK_URL, headers=auth_headers, data=None, timeout=10)
        response.raise_for_status()
        print(f"AFK心跳发送成功: {response.json()}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"AFK心跳请求失败：{e}")
        return False

def get_monthly_target():
    """每月初生成目标积分值（110-130之间）"""
    global CREDITS_MONTHLY_TARGET
    CREDITS_MONTHLY_TARGET = random.randint(CREDITS_TARGET_MIN, CREDITS_TARGET_MAX)
    print(f"[积分控制] 本月目标积分已设置为: {CREDITS_MONTHLY_TARGET}")
    return CREDITS_MONTHLY_TARGET

def check_and_init_monthly_target():
    """检查是否需要初始化月度目标"""
    global CREDITS_MONTHLY_TARGET
    today = datetime.now(timezone.utc).date()
    
    # 如果还没有设置月度目标，则设置
    if CREDITS_MONTHLY_TARGET is None:
        get_monthly_target()
    
    # 检查是否是新的一个月（每月1号时重新生成）
    if today.day == 1:
        get_monthly_target()

def should_send_heartbeat(credits):
    """根据当前积分判断是否应该发送心跳"""
    check_and_init_monthly_target()
    
    if credits < CREDITS_MONTHLY_TARGET:
        # 积分不足，需要发送心跳增加积分
        print(f"[积分控制] 当前积分 {credits} < 目标积分 {CREDITS_MONTHLY_TARGET}，将继续发送心跳")
        return True
    elif credits > CREDITS_MONTHLY_TARGET:
        # 积分过多，停止发送心跳
        print(f"[积分控制] 当前积分 {credits} > 目标积分 {CREDITS_MONTHLY_TARGET}，停止发送心跳以保持积分")
        return False
    else:
        # 积分正好等于目标，停止发送心跳
        print(f"[积分控制] 当前积分 {credits} = 目标积分 {CREDITS_MONTHLY_TARGET}，已达到目标")
        return False

def main_loop():
    """主循环逻辑"""
    token = login()
    if not token:
        return

    while True:
        # 1. 获取最新的用户信息
        user_info = get_user_info(token)
        if not user_info:
            print("无法获取用户信息，将在60秒后重试...")
            time.sleep(60)
            # 尝试重新登录以获取新的token
            token = login()
            if not token:
                print("重新登录失败，程序退出。")
                break
            continue

        # 2. 获取当前积分
        current_credits = user_info.get("credits")
        
        # 3. 根据积分判断是否发送心跳
        if not should_send_heartbeat(current_credits):
            print(f"[积分控制] 积分已达目标范围，程序将在5分钟后再次检查...")
            time.sleep(300)  # 每5分钟检查一次
            continue

        # 4. 解析afkRate和lastAFKHeartbeat
        afk_rate = user_info.get("afkRate")
        last_heartbeat_str = user_info.get("lastAFKHeartbeat")

        if afk_rate is None or last_heartbeat_str is None:
            print("无法从用户信息中获取 afkRate 或 lastAFKHeartbeat，将在60秒后重试...")
            time.sleep(60)
            continue
            
        if afk_rate <= 0:
            print(f"afkRate值为 {afk_rate}，不执行自动心跳。程序退出。")
            break

        # 5. 计算下一次心跳的时间
        interval_seconds = 30 / afk_rate
        last_heartbeat_dt = datetime.fromisoformat(last_heartbeat_str.replace('Z', '+00:00'))
        next_heartbeat_dt = last_heartbeat_dt + timedelta(seconds=interval_seconds)
        
        # 6. 等待直到下一次心跳时间
        now_utc = datetime.now(timezone.utc)
        wait_seconds = (next_heartbeat_dt - now_utc).total_seconds()

        print(f"AFK Rate: {afk_rate}, 基础间隔: {interval_seconds:.2f}秒")
        print(f"上次心跳时间: {last_heartbeat_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"预计下次心跳时间: {next_heartbeat_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"当前积分: {current_credits}/{CREDITS_MONTHLY_TARGET}")
        
        if wait_seconds > 0:
            print(f"等待 {wait_seconds:.2f} 秒...")
            time.sleep(wait_seconds)
        else:
            print("等待时间已过，立即执行心跳。")

        # 7. 发送心跳
        if not send_afk_heartbeat(token):
            print("心跳发送失败，将在60秒后重试...")
            time.sleep(60)
        
        # 循环将回到顶部，重新获取用户信息以开始下一次计时

if __name__ == "__main__":
    main_loop()