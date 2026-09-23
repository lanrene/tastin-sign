# -*- coding: utf-8 -*-
"""
塔斯汀小程序每日自动签到
用于 GitHub Actions 定时执行

环境变量配置（在 GitHub Settings > Secrets 中设置）：
  TASTIN_USER_TOKEN  - 用户认证 token（从抓包获取）
  TASTIN_MEMBER_PHONE - 加密手机号令牌（从抓包获取）
  TASTIN_SHOP_ID      - 门店 ID（默认 28416）
  TASTIN_VERSION      - 小程序版本号（默认 3.78.0）
  TASTIN_ACTIVITY_ID  - 可选，签到活动 ID 探测起点（默认 74，脚本会自动发现当月活动）

代理说明：
  塔斯汀 API 使用阿里云 WAF，会拦截海外数据中心 IP（如 GitHub Actions）。
  脚本会先尝试直连，若检测到 WAF 拦截（403/405），自动切换到国内免费代理重试。
  代理库使用改进版 freeproxy（fork）：用 ip2region 本地离线库做地理定位（替代逐个 IP 调外部
  地理API），并"找到几个可用代理即停"，把原本几十分钟~数小时的代理准备压缩到秒级。
  依赖见 requirements.txt（仅代理模式需要，本地直连无需安装）。
"""

import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime
from zoneinfo import ZoneInfo

# 强制使用上海时区（GitHub Actions runner 默认 UTC）
_TZ_SHANGHAI = ZoneInfo("Asia/Shanghai")


def _now() -> datetime:
    """当前北京时间"""
    return datetime.now(_TZ_SHANGHAI)


# 是否在 GitHub Actions 环境中运行（Actions 的海外 IP 必定被 WAF 拦截，直接走代理）
_IN_ACTIONS = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

# 单时段方案：每天只用一个时段触发，靠“单次运行内多次指数退避重试”兜住偶发的代理失效，
# 而不用一天多个时段（多时段容易被风控盯上）。
_MAX_RETRIES = 5             # 单次运行内最多尝试次数
_MAX_TOTAL_SECONDS = 900     # 总时长上限（秒），约 15 分钟
_BACKOFF_BASE = 30           # 指数退避基数（秒）：30 / 60 / 120 / 240 ...

# GitHub Actions 环境证书链可能不完整，跳过验证
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# ============ 配置 ============
USER_TOKEN = os.environ.get("TASTIN_USER_TOKEN", "")
MEMBER_PHONE = os.environ.get("TASTIN_MEMBER_PHONE", "")
SHOP_ID = os.environ.get("TASTIN_SHOP_ID", "28416")
VERSION = os.environ.get("TASTIN_VERSION", "3.78.0")

# 邮件通知配置（可选，配置后 token 过期会发邮件提醒更新 Secret）
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TO = os.environ.get("SMTP_TO", "")

# pushplus通知配置（可选）
PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")

# 签到结果也发邮件？设为 1 开启，默认只发 token 过期提醒
SMTP_NOTIFY_SIGN = os.environ.get("SMTP_NOTIFY_SIGN", "").lower() in ("1", "true", "yes")

BASE_URL = "https://sss-web.tastientech.com"

HEADERS = {
    "Content-Type": "application/json",
    "user-token": USER_TOKEN,
    "gray-shop-id": SHOP_ID,
    "channel": "1",
    "version": VERSION,
    "xweb_xhr": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 "
        "MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
        "MiniProgramEnv/Windows WindowsWechat/WMPF "
        "WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541b36) XWEB/20089"
    ),
    "Referer": "https://servicewechat.com/wx557473f23153a429/537/page-frame.html",
}


# ============ 请求工具（直连 + 代理回退） ============
_proxy_client = None      # 复用同一个 ProxiedSessionClient（内含已抓取的候选代理池）
_working_proxies = []     # fetch_working 验证出的可用代理（requests 格式 dict 列表）
_waf_blocked = False

# 代理源：只用免浏览器抓取的国内源（快代理/齐云/开心/89ip/TheSpeedX/ProxyScrape）
# 已剔除 GoodIPS：实测约 34s 且返回 0 个代理，纯浪费
_PROXY_SOURCES = [
    "KuaidailiProxiedSession", "QiyunipProxiedSession", "KxdailiProxiedSession",
    "IP89ProxiedSession", "TheSpeedXProxiedSession", "ProxyScrapeProxiedSession",
]


def _is_waf_response(result: dict) -> bool:
    """检测阿里云 WAF 拦截（返回 HTML 而非 JSON，或 403/405）"""
    code = result.get("code")
    msg = str(result.get("msg", ""))
    if code in (403, 405):
        return True
    if "<!doctype" in msg.lower() or "<html" in msg.lower():
        return True
    return False


def _is_network_error(result: dict) -> bool:
    """判断是否为网络/代理故障（请求未送达服务器），区别于服务器返回的业务错误。
    code == -1 是脚本内部标记：直连异常，或代理池整体失效导致请求发不出去。"""
    return result.get("code") == -1


def _direct_request(method: str, path: str, body: dict | None = None) -> dict:
    """直连请求（urllib，无额外依赖）"""
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace") if e.fp else ""
        return {"code": e.code, "msg": f"HTTP {e.code}: {body_text[:200]}", "result": None}
    except Exception as e:
        return {"code": -1, "msg": str(e), "result": None}


def _get_working_proxies() -> list:
    """懒初始化：抓取国内免费代理，并直接拿塔斯汀接口并发验证，凑够几个可用代理即停。"""
    global _proxy_client, _working_proxies
    if _working_proxies:
        return _working_proxies
    try:
        from freeproxy.freeproxy import ProxiedSessionClient
    except ImportError:
        print("[proxy] 错误：未安装代理库，请运行 pip install -r requirements.txt")
        sys.exit(1)
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    def _valid(resp)
