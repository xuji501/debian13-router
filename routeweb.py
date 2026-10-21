#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路由管理 Web 系统 (RouteWeb)
- 纯标准库实现, 无需安装任何依赖
- 监听所有本地地址 :8080（LAN + VPN 隧道地址），来源按白名单校验（内网 / 活动隧道网段）
- 需登录
- 功能:
  仪表盘(接口/转发/NAT/服务状态/DHCP/租约/改密码)
  端口转发(DNAT)增删
  DHCP 静态保留增删
  虚拟专网(VPN): PPTP / L2TP / OpenVPN / IKEv2-IPsec / WireGuard 安装检测+配置+服务管理
  网络配置: 静态路由增删(持久化)
  防火墙: 策略(input/output/forward)设置 + 端口放行(按 wan/lan 接口) + 拒绝规则(DROP)
  流量监视: nftables 命名计数器按类型汇总 + /proc/net/dev 接口速率, 仪表盘实时展示
- 后端以 root 运行, 所有命令均为白名单+参数校验, 禁止任意命令执行
"""
import http.server
import socketserver
import urllib.parse
import json
import subprocess
import os
import hashlib
import secrets
import re
import html
import time
import sys
import socket
import threading

# ============ 安装配置 ============
# 由 install.sh 在部署时写入 /etc/routeweb/config.json; 文件缺失时回退默认值,
# 保证"拷贝 routeweb.py 直接跑"的旧用法仍然可用。
CONFIG_FILE = os.environ.get('ROUTEWEB_CONFIG') or '/etc/routeweb/config.json'
CFG_DEF = {
    'wan_if': 'ens32',
    'lan_if': 'ens34',
    'wan_ip': '',
    'wan_gw': '10.10.173.1',
    'lan_ip': '172.16.1.1',
    'lan_net': '172.16.1.0/24',
    'upstream_dns': ['218.2.2.2', '218.4.4.4'],
    'web_port': 8080,
    'domain': 'lan',
}


def load_cfg():
    c = dict(CFG_DEF)
    try:
        with open(CONFIG_FILE) as f:
            d = json.load(f)
        for k in list(c.keys()):
            if k in d and d[k] not in (None, ''):
                c[k] = d[k]
    except Exception:
        pass
    dns = c.get('upstream_dns')
    if isinstance(dns, str):
        dns = [x.strip() for x in re.split(r'[,\s]+', dns) if x.strip()]
    c['upstream_dns'] = dns or list(CFG_DEF['upstream_dns'])
    return c


CFG = load_cfg()
HOST = str(CFG['lan_ip'])   # LAN 网关地址: DHCP 下发 / NAT / 页面展示都用它
LISTEN = '0.0.0.0'  # 监听所有本地地址: LAN + 动态出现的 VPN 隧道地址(来源仍按白名单校验)
PORT = int(CFG['web_port'])
APP_DIR = '/opt/routeweb'
STATE_FILE = os.path.join(APP_DIR, 'state.json')
AUTH_FILE = os.path.join(APP_DIR, 'auth.json')
LEASE_FILE = '/var/lib/dnsmasq/dnsmasq.leases'
ACCT_FILE = '/etc/nftables-acct.conf'
DEFAULT_PW = 'admin@route'
SESSION_TTL = 3600
# ---- 版权信息(页面最下方常驻) ----
APP_VENDOR = '起点火箭开发'        # 开发方
APP_RELDATE = '2026年10月21日'     # 发布日期
APP_VERSION = 'V1.0.1'             # 版本号

WAN_IF = str(CFG['wan_if'])
LAN_IF = str(CFG['lan_if'])
LAN_NET = str(CFG['lan_net'])
WAN_GW = str(CFG['wan_gw'])
UP_DNS = list(CFG['upstream_dns'])
WAN_IP = str(CFG.get('wan_ip') or '')   # 兜底值, 实际取值见 wan_ip_live()
DHCP_RANGE = '%s,%s,%s,%s' % (HOST.rsplit('.', 1)[0] + '.100',
                             HOST.rsplit('.', 1)[0] + '.200',
                             '255.255.255.0', '24h')

_wan_cache = {'t': 0.0, 'ip': ''}


def wan_ip_live():
    """WAN 口当前地址(WAN 走 DHCP 时地址会变, 不能只信配置文件)。"""
    now = time.time()
    if _wan_cache['ip'] and now - _wan_cache['t'] < 10:
        return _wan_cache['ip']
    ip = ''
    try:
        rc, out, err = run(['ip', '-4', '-o', 'addr', 'show', 'dev', WAN_IF])
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out or '')
        if m:
            ip = m.group(1)
    except Exception:
        ip = ''
    ip = ip or WAN_IP or '0.0.0.0'
    _wan_cache['t'] = now
    _wan_cache['ip'] = ip
    return ip

# VPN 默认虚拟网段 / 服务 / 二进制 / 安装包
# 出向隧道口的通配名: 网关作为客户端拨入远端后生成的 ppp/tun/wg 口
TUNNEL_WILD = ('ppp*', 'tun*', 'wg*')

VPN_DEF_LOCAL = {
    'pptp': '172.16.2.0/24',
    'l2tp': '172.16.3.0/24',
    'openvpn': '10.8.0.0/24',
    'ikev2': '10.9.0.0/24',
    'wireguard': '10.10.0.0/24',
}
VPN_SVC = {
    'pptp': 'pptpd',
    'l2tp': 'xl2tpd',          # l2tp 还需 strongswan
    'openvpn': 'openvpn@server',
    'ikev2': 'strongswan',
    'wireguard': 'wg-quick@wg0',
}
VPN_BIN = {
    'pptp': 'pptpd',
    'l2tp': 'xl2tpd',
    'openvpn': 'openvpn',
    'ikev2': 'swanctl',
    'wireguard': 'wg',
}
# OpenVPN 相关目录: 抽成常量便于导出/测试时替换
OVPN_PKI = '/etc/openvpn/pki'            # 服务端 PKI(CA / 服务端证书 / 客户端证书)
OVPN_CLIENT_DIR = '/etc/openvpn/client'   # 网关作为 OpenVPN 客户端(拨号端)的配置目录
VPN_PKGS = {
    'pptp': 'pptpd',
    'l2tp': 'xl2tpd strongswan',
    'openvpn': 'openvpn',
    'ikev2': 'strongswan',
    'wireguard': 'wireguard',
}
VPN_LABEL = {
    'pptp': 'PPTP',
    'l2tp': 'L2TP',
    'openvpn': 'OpenVPN',
    'ikev2': 'IKEv2 / IPsec',
    'wireguard': 'WireGuard',
}

# 流量分类: 由 nftables 命名计数器(c_<key>)按端口/协议汇总
TRAFFIC_CLASSES = [
    {'key': 'web',    'label': 'Web 网页',   'ports': [80, 443, 8080, 8443], 'color': '#2e7dd1'},
    {'key': 'dns',    'label': 'DNS 解析',   'ports': [53], 'color': '#7b61ff'},
    {'key': 'ssh',    'label': 'SSH 远程',   'ports': [22], 'color': '#0f9d8c'},
    {'key': 'mail',   'label': '邮件服务',   'ports': [25, 110, 143, 465, 587, 993, 995], 'color': '#d99a00'},
    {'key': 'file',   'label': '文件共享',   'ports': [20, 21, 139, 445, 2049, 873], 'color': '#2e9e5b'},
    {'key': 'remote', 'label': '远程桌面',   'ports': [3389, 5900], 'color': '#d9534f'},
    {'key': 'db',     'label': '数据库',     'ports': [1433, 1521, 3306, 5432, 6379, 27017], 'color': '#8a5cd6'},
    {'key': 'vpn',    'label': 'VPN 隧道',   'ports': [1723, 1194, 500, 4500, 1701, 51820], 'color': '#17a2b8'},
    {'key': 'icmp',   'label': 'ICMP 探测',  'ports': [], 'color': '#5c6b7a'},
    {'key': 'other',  'label': '其他流量',   'ports': [], 'color': '#9aa7b4'},
]
TRAFFIC_KEYS = [c['key'] for c in TRAFFIC_CLASSES]

# DHCP 服务默认配置
_MASK_CACHE = {}


def _net_mask(cidr):
    """CIDR 前缀 -> 点分掩码。"""
    try:
        n = max(0, min(32, int(str(cidr).split('/')[1])))
    except Exception:
        n = 24
    if n not in _MASK_CACHE:
        bits = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
        _MASK_CACHE[n] = '.'.join(str((bits >> s) & 0xFF) for s in (24, 16, 8, 0))
    return _MASK_CACHE[n]


def _dhcp_def():
    """按 LAN 网段推算 DHCP 默认池, 避免换网段后下发错误地址。"""
    base = HOST.rsplit('.', 1)[0]
    lo, hi = base + '.100', base + '.200'
    try:
        import ipaddress
        net = ipaddress.ip_network(LAN_NET, strict=False)
        if net.num_addresses >= 256:
            lo = str(net.network_address + 100)
            hi = str(min(net.network_address + 200, net.broadcast_address - 1))
        else:
            lo = str(net.network_address + 2)
            hi = str(net.broadcast_address - 1)
    except Exception:
        pass
    return {
        'enabled': True,
        'start': lo,
        'end': hi,
        'mask': _net_mask(LAN_NET),
        'lease': '24h',
        'router': HOST,
        'dns': HOST,
        'domain': str(CFG.get('domain') or 'lan'),
    }


DHCP_DEF = _dhcp_def()

sessions = {}  # token -> {'exp': ts}

# ============ 认证 ============
def load_auth():
    if not os.path.exists(AUTH_FILE):
        os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
        with open(AUTH_FILE, 'w') as f:
            json.dump({'pw': hashpw(DEFAULT_PW)}, f)
    with open(AUTH_FILE) as f:
        return json.load(f).get('pw')

def save_auth(pwhash):
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, 'w') as f:
        json.dump({'pw': pwhash}, f)

def hashpw(p):
    salt = secrets.token_hex(8)
    return salt + ':' + hashlib.sha256((salt + p).encode()).hexdigest()

def checkpw(p, stored):
    if ':' not in stored:
        return False
    salt, h = stored.split(':', 1)
    return secrets.compare_digest(h, hashlib.sha256((salt + p).encode()).hexdigest())

# ============ 状态 ============
def default_state():
    vpn = {k: {'enabled': False, 'local': v} for k, v in VPN_DEF_LOCAL.items()}
    for p in ('pptp', 'l2tp', 'ikev2'):
        vpn[p]['users'] = []
    vpn['l2tp']['psk'] = ''
    vpn['openvpn']['clients'] = []
    vpn['wireguard']['peers'] = []
    return {
        'port_forwards': [],
        'dhcp_static': [],
        'static_routes': [],
        'firewall': {'input': 'accept', 'output': 'accept', 'forward': 'accept',
                     'port_allows': [], 'deny_rules': []},
        'vpn': vpn,
        'dhcp': dict(DHCP_DEF),
        'ovpn_clients': [],
        'l2tp_clients': [],
        'pptp_clients': [],
        'web_access': {'vpn': True, 'extra': ''},
    }

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                s = json.load(f)
            # 兼容旧版本: 补齐缺失字段
            d = default_state()
            for k, v in d.items():
                if k not in s:
                    s[k] = v
            for k, v in d['vpn'].items():
                if k not in s['vpn']:
                    s['vpn'][k] = v
            return s
        except Exception:
            pass
    return default_state()

def save_state(s):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(s, f, indent=2)

# ============ 校验 ============
def is_ip(s):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', s or ''):
        return False
    return all(0 <= int(x) <= 255 for x in s.split('.'))

def is_cidr(s):
    if '/' not in (s or ''):
        return False
    ip, _, mask = s.partition('/')
    if not is_ip(ip):
        return False
    return mask.isdigit() and 0 <= int(mask) <= 32

def is_port(s):
    return str(s).isdigit() and 1 <= int(s) <= 65535

def is_mac(s):
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', s or ''))

def is_proto(s):
    return s in ('tcp', 'udp')

def is_vpn_user(s):
    return bool(re.match(r'^[A-Za-z0-9_.@-]{1,32}$', s or ''))

def is_vpn_pw(s):
    return bool(s) and len(s) <= 64 and '\n' not in s and '"' not in s and '\\' not in s

def is_psk(s):
    return bool(s) and len(s) <= 64 and re.match(r'^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,64}$', s or '')

def is_wg_key(s):
    s = (s or '').strip()
    if not re.match(r'^[A-Za-z0-9+/]{43}=$', s):
        return False
    try:
        # 严格校验: 必须解码为 32 字节且可无损往返;
        # 否则 wg setconf 会报 "not the correct length or format", 服务启动失败。
        import base64 as _b64
        raw = _b64.b64decode(s, validate=True)
        return len(raw) == 32 and _b64.b64encode(raw).decode() == s
    except Exception:
        return False

def safe_file(s):
    """去除换行, 防止写入配置造成注入。"""
    return (s or '').replace('\n', '').replace('\r', '')

# ============ 命令执行 (白名单) ============
def run(args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, '', str(e)

def run_in(args, inp=''):
    try:
        r = subprocess.run(args, input=inp, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, '', str(e)

# ============ 配置生成: nftables (含防火墙策略 / 端口放行 / VPN) ============
def deny_match(r):
    """把一条拒绝规则翻译成 nft 匹配片段。"""
    parts = []
    iface = r.get('iface', 'wan')
    if iface == 'wan':
        parts.append('iifname "%s"' % WAN_IF)
    elif iface == 'lan':
        parts.append('iifname "%s"' % LAN_IF)
    src = r.get('src') or ''
    if src:
        parts.append('ip saddr %s' % src)
    proto = r.get('proto', 'tcp')
    if proto == 'icmp':
        parts.append('ip protocol icmp')
    elif proto in ('tcp', 'udp') and r.get('port'):
        parts.append('%s dport %s' % (proto, r['port']))
    return ' '.join(parts)


def gen_acct():
    """流量统计表: 在各 hook 上按类型打点(仅计数, 不做裁决)。"""
    L = ['table inet acct {']
    for c in TRAFFIC_CLASSES:
        L.append('    counter c_%s {}' % c['key'])
    for hook, chain in (('input', 'acct_in'), ('forward', 'acct_fwd')):
        L.append('    chain %s {' % chain)
        L.append('        type filter hook %s priority -140; policy accept;' % hook)
        L.append('        ip protocol icmp counter name c_icmp accept')
        L.append('        ip protocol gre counter name c_vpn accept')
        L.append('        ip protocol esp counter name c_vpn accept')
        for c in TRAFFIC_CLASSES:
            if not c['ports']:
                continue
            plist = ', '.join(str(p) for p in c['ports'])
            L.append('        meta l4proto { tcp, udp } th dport { %s } counter name c_%s accept'
                     % (plist, c['key']))
            L.append('        meta l4proto { tcp, udp } th sport { %s } counter name c_%s accept'
                     % (plist, c['key']))
        L.append('        counter name c_other accept')
        L.append('    }')
    L.append('}')
    return L


def gen_nft(state):
    fw = state.get('firewall', {})
    in_pol = fw.get('input', 'accept')
    out_pol = fw.get('output', 'accept')
    fwd_pol = fw.get('forward', 'accept')
    pas = fw.get('port_allows', [])
    deny = fw.get('deny_rules', [])
    vpn = state.get('vpn', {})
    pf = state.get('port_forwards', [])
    L = []
    L.append('# 由 RouteWeb 生成')
    # 只重建 filter / nat, 保留 acct 统计表, 避免改防火墙规则时流量统计被清零
    L.append('add table inet filter')
    L.append('flush table inet filter')
    L.append('add table inet nat')
    L.append('flush table inet nat')
    L.append('table inet filter {')
    # 每条拒绝规则一个命名计数器(d<idx>), 用于统计命中
    for i in range(len(deny)):
        L.append('    counter d%d {}' % i)
    # input
    L.append('    chain input {')
    L.append('        type filter hook input priority filter; policy %s;' % in_pol)
    L.append('        ct state established,related accept')
    L.append('        iifname "lo" accept')
    L.append('        iifname "%s" tcp dport %d accept' % (LAN_IF, PORT))  # 管理口保底, 防止自锁
    # VPN 隧道口放行管理页面(网关作为客户端拨入远端后, 可通过隧道地址登录)
    for tn in ('ppp*', 'tun*', 'tap*', 'wg*'):
        L.append('        iifname "%s" tcp dport %d accept' % (tn, PORT))
    # 管理页面不对外网开放(保持原有安全边界: 仅内网 + 隧道); 若显式放行 WAN 8080 则以其为准, 故放在放行之后
    for i, r in enumerate(deny):
        if r.get('chain') == 'input':
            L.append('        %s counter name d%d drop' % (deny_match(r), i))
    L.append('        iifname "%s" accept' % LAN_IF)  # 管理网段始终信任
    for pa in pas:
        dev = WAN_IF if pa.get('iface') == 'wan' else LAN_IF
        L.append('        iifname "%s" %s dport %s accept' % (dev, pa['proto'], pa['port']))
    L.append('        iifname "%s" tcp dport %d drop' % (WAN_IF, PORT))
    if in_pol == 'drop':
        L.append('        ip protocol icmp accept')
    L.append('    }')
    # forward
    L.append('    chain forward {')
    L.append('        type filter hook forward priority filter; policy %s;' % fwd_pol)
    L.append('        ct state established,related accept')
    for i, r in enumerate(deny):
        if r.get('chain') == 'forward':
            L.append('        %s counter name d%d drop' % (deny_match(r), i))
    L.append('        iifname "%s" oifname "%s" accept' % (LAN_IF, WAN_IF))
    # 内网 -> 隧道(网关作为客户端拨入远端): 让 LAN 主机能访问远端内网
    for tn in TUNNEL_WILD:
        L.append('        iifname "%s" oifname "%s" accept' % (LAN_IF, tn))
    for name in VPN_DEF_LOCAL:
        v = vpn.get(name, {})
        if v.get('enabled') and is_cidr(v.get('local', '')):
            L.append('        ip saddr %s oifname "%s" accept' % (v['local'], WAN_IF))
            # 拨入的 VPN 客户端 -> 出向隧道: 让 VPN 客户端也能访问远端内网
            # (只放行 WAN 的话, forward 策略为 drop 时客户端访问远端内网会被丢)
            for tn in TUNNEL_WILD:
                L.append('        ip saddr %s oifname "%s" accept' % (v['local'], tn))
    for p in pf:
        L.append('        iifname "%s" oifname "%s" %s dport %s accept' % (WAN_IF, LAN_IF, p['proto'], p['ext_port']))
    if vpn.get('pptp', {}).get('enabled'):
        L.append('        iifname "%s" ip protocol gre accept' % WAN_IF)
        L.append('        iifname "%s" tcp dport 1723 accept' % WAN_IF)
    if vpn.get('l2tp', {}).get('enabled') or vpn.get('ikev2', {}).get('enabled'):
        L.append('        iifname "%s" udp dport 500 accept' % WAN_IF)
        L.append('        iifname "%s" udp dport 4500 accept' % WAN_IF)
        L.append('        iifname "%s" ip protocol esp accept' % WAN_IF)
    L.append('    }')
    L.append('    chain output { type filter hook output priority filter; policy %s; }' % out_pol)
    L.append('}')
    # nat
    L.append('table inet nat {')
    L.append('    chain postrouting {')
    L.append('        type nat hook postrouting priority srcnat; policy accept;')
    L.append('        oifname "%s" ip saddr %s masquerade' % (WAN_IF, LAN_NET))
    # 内网访问隧道对端/远端内网时必须做源地址转换: 远端路由器只认识隧道地址,
    # 不做 SNAT 时回程包没有到 172.16.1.0/24 的路由, 表现为"能发出、收不到回包"。
    for tn in TUNNEL_WILD:
        L.append('        oifname "%s" ip saddr %s masquerade' % (tn, LAN_NET))
    for name in VPN_DEF_LOCAL:
        v = vpn.get(name, {})
        if v.get('enabled') and is_cidr(v.get('local', '')):
            L.append('        oifname "%s" ip saddr %s masquerade' % (WAN_IF, v['local']))
            # 拨入的 VPN 客户端访问远端内网时同样必须做源地址转换, 否则源地址仍是
            # 10.8.0.x 之类, 远端没有回程路由 -> "能发出、收不到回包"(表现为访问远端不通, 但上网正常)
            for tn in TUNNEL_WILD:
                L.append('        oifname "%s" ip saddr %s masquerade' % (tn, v['local']))
    L.append('    }')
    L.append('    chain prerouting {')
    L.append('        type nat hook prerouting priority dstnat;')
    for p in pf:
        L.append('        %s dport %s dnat ip to %s:%s' % (p['proto'], p['ext_port'], p['int_ip'], p['int_port']))
    L.append('    }')
    L.append('}')
    return '\n'.join(L) + '\n'


def ensure_acct(force=False):
    """确保流量统计表存在。已存在则原样保留(累计计数不清零)。"""
    if not force:
        rc, out, err = run(['nft', 'list', 'table', 'inet', 'acct'])
        if rc == 0:
            return 0, '', ''
    cfg = '\n'.join(gen_acct()) + '\n'
    try:
        with open(ACCT_FILE, 'w') as f:
            f.write(cfg)
    except Exception as e:
        return -1, '', str(e)
    return run(['nft', '-f', ACCT_FILE])


def apply_nft(state):
    cfg = gen_nft(state)
    with open('/etc/nftables.conf', 'w') as f:
        f.write(cfg)
    rc, out, err = run(['nft', '-f', '/etc/nftables.conf'])
    if rc == 0:
        ar, ao, ae = ensure_acct()
        if ar != 0:
            return ar, ao, ae
    return rc, out, err

# ============ 配置生成: dnsmasq ============
def gen_dnsmasq(state):
    ds = state.get('dhcp_static', [])
    dh = state.get('dhcp', DHCP_DEF)
    L = []
    L.append('# 由 RouteWeb 生成')
    L.append('bind-dynamic')
    L.append('interface=%s' % LAN_IF)
    for d in UP_DNS:
        L.append('server=%s' % d)
    L.append('cache-size=1000')
    L.append('domain-needed')
    L.append('bogus-priv')
    L.append('stop-dns-rebind')
    L.append('dhcp-authoritative')
    L.append('dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases')
    L.append('log-queries')
    L.append('log-dhcp')
    if dh.get('enabled', True):
        L.append('dhcp-range=%s,%s,%s,%s' % (
            dh.get('start', '172.16.1.100'), dh.get('end', '172.16.1.200'),
            dh.get('mask', '255.255.255.0'), dh.get('lease', '24h')))
        L.append('dhcp-option=option:router,%s' % dh.get('router', HOST))
        dns = dh.get('dns', HOST)
        for dnss in [x.strip() for x in str(dns).split(',') if x.strip()]:
            L.append('dhcp-option=option:dns-server,%s' % dnss)
        if dh.get('domain'):
            L.append('dhcp-option=option:domain-name,%s' % dh.get('domain'))
    for d in ds:
        L.append('dhcp-host=%s,%s,%s' % (d['mac'], d['ip'], d.get('desc', 'static')))
    return '\n'.join(L) + '\n'

def apply_dnsmasq(state):
    cfg = gen_dnsmasq(state)
    with open('/etc/dnsmasq.conf', 'w') as f:
        f.write(cfg)
    rc, out, err = run(['systemctl', 'restart', 'dnsmasq'])
    return rc, out, err

# ============ 静态路由 (持久化) ============
def apply_routes(state):
    for r in state.get('static_routes', []):
        dest = r.get('dest', '')
        if not is_cidr(dest):
            continue
        args = ['ip', 'route', 'replace', dest]
        if r.get('gw') and is_ip(r['gw']):
            args += ['via', r['gw']]
        if r.get('dev'):
            args += ['dev', r['dev']]
        run(args)

# ============ 接口地址配置 (WAN / LAN, 经 NetworkManager 持久化) ============
def save_cfg_file(c):
    """把 CFG 写回 /etc/routeweb/config.json (只保留已知键)。"""
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        d = {}
        for k in CFG_DEF:
            d[k] = c.get(k, CFG_DEF[k])
        with open(CONFIG_FILE, 'w') as f:
            json.dump(d, f, indent=2)
        return True
    except Exception:
        return False

def reload_cfg():
    """重新读取 config.json 并刷新模块级常量(无需重启进程)。"""
    global CFG, HOST, PORT, WAN_IF, LAN_IF, LAN_NET, WAN_GW, UP_DNS, WAN_IP, DHCP_DEF, _wan_cache
    CFG = load_cfg()
    HOST = str(CFG['lan_ip'])
    PORT = int(CFG['web_port'])
    WAN_IF = str(CFG['wan_if'])
    LAN_IF = str(CFG['lan_if'])
    LAN_NET = str(CFG['lan_net'])
    WAN_GW = str(CFG['wan_gw'])
    UP_DNS = list(CFG['upstream_dns'])
    WAN_IP = str(CFG.get('wan_ip') or '')
    DHCP_DEF = _dhcp_def()
    _wan_cache = {'t': 0.0, 'ip': ''}

def nm_conn_name(dev):
    """查找设备对应的 NetworkManager 连接名。"""
    if not dev:
        return ''
    rc, out, err = run(['nmcli', '-t', '-f', 'NAME,DEVICE', 'con', 'show'])
    for ln in (out or '').splitlines():
        n, _, d = ln.partition(':')
        if d.strip() == dev:
            return n.strip()
    return ''

def nm_conn_get(name, prop):
    """读连接属性; 未设置(nmcli 显示 --)返回空串。"""
    if not name:
        return ''
    rc, out, err = run(['nmcli', '-g', prop, 'con', 'show', name])
    v = (out or '').strip()
    return '' if v == '--' else v

def iface_addr_live(dev):
    """接口当前 IPv4 地址(带前缀)。"""
    if not dev:
        return ''
    rc, out, err = run(['ip', '-4', '-o', 'addr', 'show', 'dev', dev])
    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', out or '')
    return m.group(1) if m else ''

def apply_iface_v4(dev, mode, cidr='', gw='', dns=''):
    """经 NetworkManager 修改接口 IPv4 并立即生效(写入连接配置, 重启不丢)。
    失败自动回滚到修改前的连接参数。返回 (ok, detail)。"""
    name = nm_conn_name(dev)
    if not name:
        return False, '未找到设备 %s 的 NetworkManager 连接(仅支持 NM 管理的接口)' % dev
    backup = {p: nm_conn_get(name, 'ipv4.' + p) for p in ('method', 'addresses', 'gateway', 'dns')}
    def restore():
        # 先恢复地址最后切回 method: 与正向应用同理, manual 必须已有地址
        for p in ('addresses', 'gateway', 'dns'):
            run(['nmcli', 'con', 'mod', name, 'ipv4.' + p, backup[p]])
        run(['nmcli', 'con', 'mod', name, 'ipv4.method', backup['method'] or 'auto'])
        run(['nmcli', 'con', 'up', name])
    # dad-timeout=0: 本环境 WAN/LAN 同处一个二层域, 内核会对跨网卡的 ARP 探测代答,
    # 开启 DAD 时 NM 会误判"地址已被占用"导致 con up 失败(实测 47s 超时后 ip-config-unavailable)。
    dad = ['nmcli', 'con', 'mod', name, 'ipv4.dad-timeout', '0']
    if mode == 'dhcp':
        mods = [dad, ['nmcli', 'con', 'mod', name, 'ipv4.method', 'auto']]
        for p in ('addresses', 'gateway', 'dns'):
            mods.append(['nmcli', 'con', 'mod', name, 'ipv4.' + p, ''])
    else:
        # 先设地址最后切 manual: nmcli 校验 "method manual 需要至少一个地址",
        # 无地址的连接先切 manual 会直接报错。
        mods = [dad,
                ['nmcli', 'con', 'mod', name, 'ipv4.addresses', cidr],
                ['nmcli', 'con', 'mod', name, 'ipv4.gateway', gw or ''],
                ['nmcli', 'con', 'mod', name, 'ipv4.dns', dns or ''],
                ['nmcli', 'con', 'mod', name, 'ipv4.method', 'manual']]
    for m in mods:
        rc, out, err = run(m)
        if rc != 0:
            restore()
            return False, 'nmcli 修改失败(已回滚): %s' % ((err or out).strip()[:150])
    rc, out, err = run(['nmcli', 'con', 'up', name])
    if rc != 0:
        restore()
        return False, '接口 %s 激活失败(已回滚): %s' % (dev, (err or out).strip()[:150])
    if mode == 'static':
        time.sleep(1.5)
        live = iface_addr_live(dev)
        if live.split('/')[0] != cidr.split('/')[0]:
            restore()
            return False, '新地址未生效(当前 %s), 已回滚' % (live or '无地址')
    return True, ''

# ============ VPN: 安装检测 ============
def vpn_installed(proto):
    binname = VPN_BIN.get(proto)
    rc, out, err = run(['bash', '-c', 'command -v %s' % binname])
    return rc == 0 and out.strip() != ''

def vpn_active(proto):
    svc = VPN_SVC.get(proto)
    if proto == 'l2tp':
        rc, out, err = run(['systemctl', 'is-active', 'xl2tpd'])
        return out.strip() == 'active'
    rc, out, err = run(['systemctl', 'is-active', svc])
    return out.strip() == 'active'

# ============ VPN: OpenVPN / IKEv2 的 openssl PKI ============
def _ovpn_sign(base, name, eku):
    """用 CA 签发证书并写入扩展用途。

    OpenVPN 2.6+ 客户端的 `remote-cert-tls server` 会校验服务端证书的
    extendedKeyUsage; 旧版裸签(不带扩展)会直接报
    "Certificate does not have key usage extension / VERIFY KU ERROR"。
    """
    ext = base + '/' + name + '.ext'
    with open(ext, 'w') as f:
        f.write('basicConstraints = CA:FALSE\n')
        f.write('subjectKeyIdentifier = hash\n')
        if eku == 'serverAuth':
            f.write('keyUsage = critical,digitalSignature,keyEncipherment\n')
        else:
            f.write('keyUsage = critical,digitalSignature\n')
        f.write('extendedKeyUsage = %s\n' % eku)
    run(['openssl', 'x509', '-req', '-in', base + '/' + name + '.csr',
         '-CA', base + '/ca.crt', '-CAkey', base + '/ca.key', '-CAcreateserial',
         '-days', '3650', '-out', base + '/' + name + '.crt', '-extfile', ext])
    return os.path.exists(base + '/' + name + '.crt')


def _ovpn_cert_has_eku(crt, eku_text):
    """证书是否含指定的扩展用途文本(如 'TLS Web Server Authentication')。"""
    if not os.path.exists(crt):
        return False
    rc, out, err = run(['openssl', 'x509', '-in', crt, '-noout', '-text'])
    return rc == 0 and eku_text in (out or '')


def ovpn_ensure_pki():
    base = OVPN_PKI
    os.makedirs(base, exist_ok=True)
    if os.path.exists(base + '/ca.crt') and os.path.exists(base + '/server.crt') and os.path.exists(base + '/dh.pem'):
        # 旧版本签发的证书缺少扩展用途, 会让 OpenVPN 2.6+ 客户端 TLS 校验失败。
        # 这里就地重签服务端证书: CA 与私钥不变, 已分发的 .ovpn(内含 ca/client 证书)不受影响。
        if not _ovpn_cert_has_eku(base + '/server.crt', 'TLS Web Server Authentication'):
            if not os.path.exists(base + '/server.csr'):
                run(['openssl', 'req', '-new', '-key', base + '/server.key',
                     '-subj', '/CN=openvpn-server', '-out', base + '/server.csr'])
            _ovpn_sign(base, 'server', 'serverAuth')
        return True
    run(['openssl', 'genrsa', '-out', base + '/ca.key', '2048'])
    run(['openssl', 'req', '-x509', '-new', '-nodes', '-key', base + '/ca.key',
         '-subj', '/CN=RouteWeb-CA', '-days', '3650', '-out', base + '/ca.crt',
         '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    run(['openssl', 'genrsa', '-out', base + '/server.key', '2048'])
    run(['openssl', 'req', '-new', '-key', base + '/server.key', '-subj', '/CN=openvpn-server',
         '-out', base + '/server.csr'])
    _ovpn_sign(base, 'server', 'serverAuth')
    run(['openssl', 'dhparam', '-out', base + '/dh.pem', '2048'])
    return os.path.exists(base + '/ca.crt') and os.path.exists(base + '/server.crt')

def ovpn_client_cert(name):
    base = OVPN_PKI
    ovpn_ensure_pki()
    key = base + '/' + name + '.key'
    csr = base + '/' + name + '.csr'
    crt = base + '/' + name + '.crt'
    run(['openssl', 'genrsa', '-out', key, '2048'])
    run(['openssl', 'req', '-new', '-key', key, '-subj', '/CN=' + name, '-out', csr])
    _ovpn_sign(base, name, 'clientAuth')

def ovpn_server_endpoint():
    """OpenVPN 服务端的对外地址 / 端口 / 协议(写进客户端配置)。"""
    try:
        v = load_state()['vpn'].get('openvpn', {})
    except Exception:
        v = {}
    port = str(v.get('port') or 1194)
    proto = 'tcp' if str(v.get('proto') or 'udp').lower() == 'tcp' else 'udp'
    return wan_ip_live(), port, proto


def ovpn_client_conf(name, mode='full', ensure=True):
    """生成 OpenVPN 服务端签发的客户端配置(.ovpn 内容)。
    mode='full' 全流量走隧道(redirect-gateway def1)
    mode='lan'  仅访问内网(只下发内网路由, 不改动客户端默认网关)
    证书缺失且 ensure=True 时自动补签。"""
    base = OVPN_PKI
    n = safe_file(name)
    crt_p = os.path.join(base, n + '.crt')
    key_p = os.path.join(base, n + '.key')
    if ensure and not (os.path.exists(crt_p) and os.path.exists(key_p)):
        try:
            ovpn_client_cert(n)
        except Exception:
            pass
    try:
        with open(os.path.join(base, 'ca.crt')) as f:
            ca = f.read().strip()
        with open(crt_p) as f:
            crt = f.read().strip()
        with open(key_p) as f:
            key = f.read().strip()
    except Exception:
        return ''
    host, port, proto = ovpn_server_endpoint()
    lan_ip = LAN_NET.split('/')[0]
    lan_mask = cidr_mask(LAN_NET)
    L = ['# RouteWeb OpenVPN 客户端配置: %s' % n,
         '# 服务器 %s:%s (%s)' % (host, port, proto.upper()),
         'client',
         'dev tun',
         'proto ' + proto,
         'remote %s %s' % (host, port),
         'resolv-retry infinite',
         'nobind',
         'persist-key',
         'persist-tun',
         'remote-cert-tls server',
         'cipher AES-256-GCM',
         'auth SHA256',
         'verb 3',
         'mute 20']
    # 与服务端“路由推送设置”保持一致: 全流量模式才改写客户端默认网关
    try:
        _st = load_state()
    except Exception:
        _st = default_state()
    _pr = ovpn_push_routes(_st)
    if mode == 'lan':
        L.append('# 仅内网模式: 不修改客户端默认网关, 只把下列网段指向隧道')
        for _n in _pr:
            L.append('route %s %s' % (_n.split('/')[0], cidr_mask(_n)))
        L.append('dhcp-option DNS %s' % HOST)
    else:
        if ovpn_push_default(_st):
            L.append('redirect-gateway def1')
        else:
            L.append('# 未开启全流量推送: 只把下列网段指向隧道, 不影响客户端上网')
            for _n in _pr:
                L.append('route %s %s' % (_n.split('/')[0], cidr_mask(_n)))
        L.append('dhcp-option DNS %s' % HOST)
    L.append('<ca>\n%s\n</ca>' % ca)
    L.append('<cert>\n%s\n</cert>' % crt)
    L.append('<key>\n%s\n</key>' % key)
    return '\n'.join(L) + '\n'

def ikev2_ensure_pki():
    cacerts = '/etc/ipsec.d/cacerts'
    certs = '/etc/ipsec.d/certs'
    priv = '/etc/ipsec.d/private'
    os.makedirs(cacerts, exist_ok=True)
    os.makedirs(certs, exist_ok=True)
    os.makedirs(priv, exist_ok=True)
    cakey = priv + '/ca.key'
    cacrt = cacerts + '/ca.crt'
    skey = priv + '/server.key'
    scrt = certs + '/server.crt'
    if os.path.exists(cacrt) and os.path.exists(scrt):
        return True
    run(['openssl', 'genrsa', '-out', cakey, '2048'])
    run(['openssl', 'req', '-x509', '-new', '-nodes', '-key', cakey,
         '-subj', '/CN=RouteWeb-IKEv2-CA', '-days', '3650', '-out', cacrt])
    run(['openssl', 'genrsa', '-out', skey, '2048'])
    run(['openssl', 'req', '-new', '-key', skey, '-subj', '/CN=%s' % wan_ip_live(), '-out', priv + '/server.csr'])
    run(['openssl', 'x509', '-req', '-in', priv + '/server.csr', '-CA', cacrt, '-CAkey', cakey,
         '-CAcreateserial', '-days', '3650', '-out', scrt])
    return os.path.exists(cacrt) and os.path.exists(scrt)

# ============ VPN: 各协议配置文件生成 ============
def vpn_server_addr(pname, v):
    """VPN 服务端(本机隧道)地址: 手动设置 v['server'] 优先, 否则按客户端网段自动推导。
    PPTP/L2TP 默认取网段首地址, OpenVPN/WireGuard 默认取网段首地址+1,
    IKEv2 未手动设置时返回 '' (服务端地址由客户端动态获取)。"""
    s = (v.get('server') or '').strip() if isinstance(v, dict) else ''
    if s:
        return s
    local = (v.get('local', '') if isinstance(v, dict) else '') or VPN_DEF_LOCAL.get(pname, '')
    if not is_cidr(local):
        return ''
    try:
        import ipaddress as _ipa
        n = _ipa.ip_network(local, strict=False)
        if pname in ('openvpn', 'wireguard'):
            return str(_ipa.ip_address(int(n.network_address) + 1))
        if pname == 'ikev2':
            return ''
        return str(n.network_address)
    except Exception:
        return ''


def vpn_pool_range(pname, v):
    """按客户端网段的实际前缀长度计算可用地址池, 返回 (起始IP, 结束IP); 池为空返回 ('', '')。

    起点 = max(网段首地址+2, 服务端地址+1) —— 保持与原写死实现完全一致:
      PPTP/L2TP 默认服务端是网段首地址(.0), 客户端从 .2 起;
      OpenVPN 默认服务端是 .1, server 指令同样从 .2 起分配。
    终点 = 广播地址 - 1。
    """
    local = (v.get('local', '') if isinstance(v, dict) else '') or VPN_DEF_LOCAL.get(pname, '')
    if not is_cidr(local):
        return ('', '')
    try:
        import ipaddress as _ipa
        n = _ipa.ip_network(local, strict=False)
        if n.num_addresses <= 2:          # /31, /32 没有可用主机地址
            return ('', '')
        first = int(n.network_address) + 2
        last = int(n.broadcast_address) - 1
        srv = vpn_server_addr(pname, v)
        if srv:
            try:
                first = max(first, int(_ipa.ip_address(srv)) + 1)
            except Exception:
                pass
        if first > last:
            return ('', '')
        return (str(_ipa.ip_address(first)), str(_ipa.ip_address(last)))
    except Exception:
        return ('', '')


def pptp_remoteip_lines(start, end, limit=None):
    """pptpd 的 remoteip 只接受 "x.x.x.起-止"(同一个第三段内的末段范围),
    跨第三段必须拆成多行。上限由调用方决定(None 表示不限)。
    返回 (行列表, 是否被截断到 limit)。
    """
    if not start or not end:
        return ([], False)
    try:
        import ipaddress as _ipa
        lo, hi = int(_ipa.ip_address(start)), int(_ipa.ip_address(end))
    except Exception:
        return ([], False)
    total = hi - lo + 1
    if limit is None or limit <= 0:
        limit = total
    truncated = total > limit
    addrs = []
    cur = lo
    while cur <= hi and len(addrs) < limit:
        addrs.append(cur)
        cur += 1
    truncated = hi - lo + 1 > limit
    groups = {}
    for a in addrs:
        s = str(_ipa.ip_address(a))
        head, _, tail = s.rpartition('.')
        groups.setdefault(head, []).append(int(tail))
    lines = []
    for head in sorted(groups, key=lambda x: [int(p) for p in x.split('.')]):
        lst = sorted(groups[head])
        i = 0
        while i < len(lst):
            j = i
            while j + 1 < len(lst) and lst[j + 1] == lst[j] + 1:
                j += 1
            lines.append('%s.%d' % (head, lst[i]) if i == j else '%s.%d-%d' % (head, lst[i], lst[j]))
            i = j + 1
    return (lines, truncated)


def _text_file_changed(path, new_text):
    """磁盘内容与 new_text 不同则返回 True(文件不存在也视为变化)。"""
    try:
        with open(path) as f:
            return f.read() != new_text
    except Exception:
        return True


def gen_pptp_files(state):
    """生成 /etc/pptpd.conf 与 /etc/ppp/options.pptpd。

    返回 True 表示磁盘配置发生了变化。调用方据此决定是否 restart pptpd:
    pptpd 只在进程启动时读一次地址池, 服务已在运行时 systemctl start 不会
    重载配置, 会导致"页面显示新地址池、实际仍发旧网段"。
    """
    v = state['vpn']['pptp']
    local = v.get('local', VPN_DEF_LOCAL['pptp'])
    lip = vpn_server_addr('pptp', v) or local.split('/')[0]
    base = lip.rsplit('.', 1)[0]
    # pptpd 的 remoteip 只接受 "x.x.x.起始-结束"(末段范围), 不接受完整 IP 连字符写法
    _ps, _pe = vpn_pool_range('pptp', v)
    _rlines, _trunc = pptp_remoteip_lines(_ps, _pe)
    if not _rlines:                       # 网段过小: 退回传统写法, 保证配置仍可解析
        _rlines = ['%s.2-254' % base]
    buf = ['# 由 RouteWeb 生成 (PPTP)\n',
           'option /etc/ppp/options.pptpd\n',
           'logwtmp\n',
           'localip %s\n' % lip]
    try:
        _conn = int(v.get('max_connections') or 100)
        if not (1 <= _conn <= 4096):
            _conn = 100
    except Exception:
        _conn = 100
    try:
        import ipaddress as _ipx
        _pn = int(_ipx.ip_address(_pe)) - int(_ipx.ip_address(_ps)) + 1
        if _pn > 0 and _conn > _pn:
            _conn = _pn
    except Exception:
        pass
    buf.append('connections %d\n' % _conn)
    if _trunc:
        _total_addr = 0
        try:
            import ipaddress as _ipa2
            _total_addr = int(_ipa2.ip_address(_pe)) - int(_ipa2.ip_address(_ps)) + 1
        except Exception:
            pass
        buf.append('# 注意: 地址池共 %d 个地址, 已按 connections=%d 截断; '
                   '超出部分将被 pptpd 自动忽略\n' % (_total_addr, _conn))
    for _r in _rlines:
        buf.append('remoteip %s\n' % _r)
    conf_txt = ''.join(buf)
    opt_txt = ('name pptpd\n'
               'refuse-pap\nrefuse-chap\nrefuse-mschap\n'
               'require-mschap-v2\nrequire-mppe-128\n'
               'ms-dns %s\n'
               'proxyarp\nnodefaultroute\nlock\nnobsdcomp\nnovj\n' % HOST)
    changed = (_text_file_changed('/etc/pptpd.conf', conf_txt)
               or _text_file_changed('/etc/ppp/options.pptpd', opt_txt))
    with open('/etc/pptpd.conf', 'w') as f:
        f.write(conf_txt)
    with open('/etc/ppp/options.pptpd', 'w') as f:
        f.write(opt_txt)
    _write_chap_secrets(state)
    return changed

def gen_l2tp_files(state):
    v = state['vpn']['l2tp']
    local = v.get('local', VPN_DEF_LOCAL['l2tp'])
    lip = vpn_server_addr('l2tp', v) or local.split('/')[0]
    base = lip.rsplit('.', 1)[0]
    with open('/etc/xl2tpd/xl2tpd.conf', 'w') as f:
        f.write('[global]\nlisten-addr=%s\nipsec saref=no\n\n' % HOST)
        if v.get('enabled'):
            f.write('[lns default]\n')
            _lps, _lpe = vpn_pool_range('l2tp', v)
            try:
                _lconn = int(v.get('max_connections') or 100)
            except Exception:
                _lconn = 100
            if not (1 <= _lconn <= 4096):
                _lconn = 100
            _lrlines, _ = pptp_remoteip_lines(_lps, _lpe, limit=_lconn)
            if _lrlines:
                for _lr in _lrlines:
                    f.write('ip range = %s\n' % _lr)
            else:
                f.write('ip range = %s.2-%s.254\n' % (base, base))
            f.write('local ip = %s\n' % lip)
            f.write('require chap = yes\nrefuse pap = yes\nrequire authentication = yes\n')
            f.write('name = l2tpd\npppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n\n')
        # L2TP 客户端(lac): 网关拨入远端 L2TP 服务器 (autodial 自动拨号)
        for c in state.get('l2tp_clients', []):
            f.write('[lac %s]\n' % safe_file(c.get('name', '')))
            f.write('lns = %s\n' % safe_file(c.get('server', '')))
            f.write('pppoptfile = /etc/ppp/options.l2tp-%s\n' % safe_file(c.get('name', '')))
            f.write('autodial = yes\nredial = yes\nredial timeout = 10\n\n')
    with open('/etc/ppp/options.xl2tpd', 'w') as f:
        f.write('ipcp-accept-local\nipcp-accept-remote\nms-dns %s\n' % HOST)
        f.write('noccp\nauth\nmtu 1280\nmru 1280\nlock\n')
    # 每个 L2TP 客户端的 ppp 选项文件(密码内联, 避免覆盖服务端 chap-secrets)
    for c in state.get('l2tp_clients', []):
        name = safe_file(c.get('name', ''))
        os.makedirs(PPP_LOG_DIR, exist_ok=True)
        with open('/etc/ppp/options.l2tp-%s' % name, 'w') as f:
            f.write('remotename l2tp-%s\n' % name)
            f.write('ipparam %s\n' % name)
            f.write('user %s\n' % safe_file(c.get('user', '')))
            f.write('password %s\n' % safe_file(c.get('pass', '')))
            f.write('ipcp-accept-local\nipcp-accept-remote\n')
            # 同 PPTP: 客户端只能用 noauth + refuse-*, 不能用 require-mschap-v2
            f.write('noauth\nrefuse-pap\nrefuse-eap\nrefuse-chap\nrefuse-mschap\nnoccp\n')
            if c.get('defaultroute'):
                f.write('defaultroute\n')
            else:
                f.write('nodefaultroute\n')
            f.write('persist\nmaxfail 0\n')
            f.write('hide-password\ndebug\nlogfile %s\n' % ppp_log(name))
        write_nets_file(name, nets_of(c))
    _write_chap_secrets(state)

def _write_chap_secrets(state):
    lines = ['# Secrets for authentication (RouteWeb)']
    # 已禁用的账号不写入: 断开后重新拨号会被拒绝(已在线的由 vpn_user_toggle 主动踢掉)
    for u in state['vpn']['pptp'].get('users', []):
        if not u.get('disabled'):
            lines.append('%s * %s *' % (safe_file(u['user']), safe_file(u['pw'])))
    for u in state['vpn']['l2tp'].get('users', []):
        if not u.get('disabled'):
            lines.append('%s * %s *' % (safe_file(u['user']), safe_file(u['pw'])))
    with open('/etc/ppp/chap-secrets', 'w') as f:
        f.write('\n'.join(lines) + '\n')

def ovpn_static_ips(state=None):
    """已配置的固定隧道 IP(校验通过者), 按数值升序。"""
    if state is None:
        state = load_state()
    v = state.get('vpn', {}).get('openvpn', {})
    out = []
    for c in v.get('clients', []):
        ip = (c.get('ip') or '').strip()
        if not ip:
            continue
        ok, _m = ovpn_static_ip_check(ip, c.get('name'), state)
        if ok:
            out.append(ip)
    try:
        import ipaddress as _ipa
        out.sort(key=lambda x: int(_ipa.ip_address(x)))
    except Exception:
        pass
    return out


def ovpn_dyn_pool(v, state=None):
    """OpenVPN 动态地址池: 在 vpn_pool_range 之上避开已指定的固定 IP。

    固定 IP 由 CCD 下发, 不在动态池记录里; 若两者重叠, 动态客户端可能先占到
    该地址, 静态客户端连上来就会冲突。这里把动态池收缩到最小固定 IP 之前,
    从根本上避免重叠(固定 IP 建议取网段靠后的地址)。
    """
    ps, pe = vpn_pool_range('openvpn', v)
    if not ps:
        return ps, pe
    statics = ovpn_static_ips(state)
    if not statics:
        return ps, pe
    try:
        import ipaddress as _ipa
        lo, hi = int(_ipa.ip_address(ps)), int(_ipa.ip_address(pe))
        first = int(_ipa.ip_address(statics[0]))
        if first > lo:
            hi = min(hi, first - 1)
        else:
            lo = max(lo, first + 1)
        if lo > hi:
            return ('', '')
        return str(_ipa.ip_address(lo)), str(_ipa.ip_address(hi))
    except Exception:
        return ps, pe


def gen_ovpn_files(state):
    """生成 /etc/openvpn/server.conf 与各客户端 CCD。返回 True 表示 server.conf 发生变化。"""
    v = state['vpn']['openvpn']
    local = v.get('local', VPN_DEF_LOCAL['openvpn'])
    net = local.split('/')[0].rsplit('.', 1)[0] + '.0'
    port = v.get('port', 1194)
    ovpn_ensure_pki()
    conf = ['# 由 RouteWeb 生成 (OpenVPN)\n']
    conf.append('port %s\nproto udp\ndev tun\n' % port)
    # 固定 IP 依赖 subnet 拓扑(ifconfig-push 第二参数为掩码); 显式声明避免依赖版本默认值
    conf.append('topology subnet\n')
    conf.append('ca /etc/openvpn/pki/ca.crt\n')
    conf.append('cert /etc/openvpn/pki/server.crt\n')
    conf.append('key /etc/openvpn/pki/server.key\n')
    conf.append('dh /etc/openvpn/pki/dh.pem\n')
    import ipaddress as _ipa
    _srv = vpn_server_addr('openvpn', v)
    try:
        _n = _ipa.ip_network(local, strict=False)
        _nm = str(_n.netmask)
    except Exception:
        _n, _nm = None, '255.255.255.0'
    _ops, _ope = ovpn_dyn_pool(v, state)
    _dps, _dpe = vpn_pool_range('openvpn', v)
    # 有客户端指定了固定 IP 时需要收缩动态池; 但 --server 已隐含 ifconfig-pool,
    # 再显式指定会报 "Options error: --server already defines an ifconfig-pool",
    # 因此这种情况下必须改用 --server 的等价展开式(见 openvpn(8) 手册)。
    _auto = str(_ipa.ip_address(int(_n.network_address) + 1)) if _n is not None else None
    _lip = _srv or _auto or (local.split('/')[0] if local else net)
    _explicit = (_ops, _ope) != (_dps, _dpe) or bool(_srv and _auto and _srv != _auto)
    if _explicit:
        conf.append('mode server\ntls-server\n')
        conf.append('push "topology subnet"\n')
        conf.append('ifconfig %s %s\n' % (_lip, _nm))
        if not _ops and _n is not None:
            _ops = str(_ipa.ip_address(int(_ipa.ip_address(_lip)) + 1))
            _ope = str(_ipa.ip_address(int(_n.broadcast_address) - 1))
        conf.append('ifconfig-pool %s %s %s\n' % (_ops, _ope, _nm))
        conf.append('push "route-gateway %s"\n' % _lip)
    else:
        conf.append('server %s %s\n' % (str(_n.network_address) if _n is not None else net, _nm))
    conf.append('push "dhcp-option DNS %s"\n' % HOST)
    # 路由推送(可在“虚拟专网 → OpenVPN → 路由推送设置”中调整)
    for _pn in ovpn_push_routes(state):
        try:
            _pn_n = _ipa.ip_network(_pn, strict=False)
        except Exception:
            continue
        conf.append('push "route %s %s"\n' % (str(_pn_n.network_address), str(_pn_n.netmask)))
    if ovpn_push_default(state):
        conf.append('push "redirect-gateway def1"\n')
    conf.append('keepalive 10 120\ncipher AES-256-GCM\nauth SHA256\n')
    conf.append('user nobody\ngroup nogroup\npersist-key\npersist-tun\n')
    # 在线客户端需要 status(version 2 CSV, 含 time_t 与流量) + management(kick)
    conf.append('status %s 10\n' % OVPN_STATUS)
    conf.append('status-version 2\n')
    conf.append('management %s %d\n' % (OVPN_MGMT_HOST, OVPN_MGMT_PORT))
    conf.append('client-config-dir %s\n' % OVPN_CCD)
    try:
        _oc = int(v.get('max_connections') or 100)
    except Exception:
        _oc = 100
    if not (1 <= _oc <= 4096):
        _oc = 100
    try:
        _ops2, _ope2 = ovpn_dyn_pool(v, state)
        if _ops2:
            _pn = int(_ipa.ip_address(_ope2)) - int(_ipa.ip_address(_ops2)) + 1
            if _pn > 0 and _oc > _pn:
                _oc = _pn
    except Exception:
        pass
    conf.append('max-clients %d\n' % _oc)
    conf_txt = ''.join(conf)
    changed = _text_file_changed(OVPN_SERVER_CONF, conf_txt)
    with open(OVPN_SERVER_CONF, 'w') as f:
        f.write(conf_txt)
    # openvpn 降权为 nobody 后仍需写 status 文件、读 ccd 目录
    try:
        os.makedirs(OVPN_CCD, exist_ok=True)
        os.chmod(OVPN_CCD, 0o755)
        if not os.path.exists(OVPN_STATUS):
            open(OVPN_STATUS, 'w').close()
        os.chmod(OVPN_STATUS, 0o666)
    except Exception:
        pass
    # 客户端专属配置: 固定隧道 IP + 禁用标记
    try:
        ovpn_sync_ccd(state)
    except Exception:
        pass
    return changed

def gen_ipsec(state):
    """合并生成 L2TP + IKEv2 的 strongswan 配置。"""
    l2tp = state['vpn']['l2tp']
    ikev2 = state['vpn']['ikev2']
    conf = ['# 由 RouteWeb 生成 (strongSwan)\nconfig setup\n    charondebug="ike 1, knl 1, cfg 0"\n    uniqueids=no\n']
    secrets = ['# 由 RouteWeb 生成 (strongSwan secrets)\n']
    if ikev2.get('enabled'):
        ikev2_ensure_pki()
        local = ikev2.get('local', VPN_DEF_LOCAL['ikev2'])
        net = local.split('/')[0].rsplit('.', 1)[0] + '.0'
        conf.append('conn ikev2-vpn\n')
        conf.append('    auto=add\n    compress=no\n    type=tunnel\n    keyexchange=ikev2\n')
        conf.append('    fragmentation=yes\n    forceencaps=yes\n')
        conf.append('    ike=aes256-sha256-modp2048!\n    esp=aes256-sha256!\n')
        conf.append('    dpdaction=clear\n    dpddelay=300s\n    rekey=no\n')
        conf.append('    left=%%any\n    leftid=%s\n    leftcert=server.crt\n    leftsendcert=always\n' % wan_ip_live())
        conf.append('    leftsubnet=0.0.0.0/0\n    right=%%any\n    rightid=%%any\n')
        _ipool = net + '/24'
        try:
            import ipaddress as _ipa
            _ipool = str(_ipa.ip_network(local, strict=False))
        except Exception:
            pass
        _ikps, _ikpe = vpn_pool_range('ikev2', ikev2)
        if _ikps:
            try:
                _iconn = int(ikev2.get('max_connections') or 100)
                if not (1 <= _iconn <= 4096):
                    _iconn = 100
                _ilo = int(_ipa.ip_address(_ikps)); _ihi = int(_ipa.ip_address(_ikpe))
                if _ihi - _ilo + 1 > _iconn:
                    _ikpe = str(_ipa.ip_address(_ilo + _iconn - 1))
            except Exception:
                pass
            _ipool = '%s-%s' % (_ikps, _ikpe)
        conf.append('    rightauth=eap-mschapv2\n    rightsourceip=%s\n    rightdns=%s\n' % (_ipool, HOST))
        _isrv = vpn_server_addr('ikev2', ikev2)
        if _isrv:
            conf.append('    leftsourceip=%s\n' % _isrv)
        secrets.append(': RSA server.key\n')
        for u in ikev2.get('users', []):
            if u.get('disabled'):
                continue
            secrets.append('%s : EAP "%s"\n' % (safe_file(u['user']), safe_file(u['pw'])))
    if l2tp.get('enabled'):
        psk = safe_file(l2tp.get('psk', ''))
        conf.append('conn l2tp-psk\n')
        conf.append('    auto=add\n    keyexchange=ikev1\n    authby=secret\n    type=transport\n')
        conf.append('    left=%%any\n    leftprotoport=17/1701\n    right=%%any\n    rightprotoport=17/1701\n')
        secrets.append(': PSK "%s"\n' % psk)
    with open('/etc/ipsec.conf', 'w') as f:
        f.write(''.join(conf))
    with open('/etc/ipsec.secrets', 'w') as f:
        f.write(''.join(secrets))

def gen_wg_files(state):
    v = state['vpn']['wireguard']
    local = v.get('local', VPN_DEF_LOCAL['wireguard'])
    addr = local  # e.g. 10.10.0.0/24 -> interface address 10.10.0.1/24
    if '/' in local:
        net, _, m = local.partition('/')
        a, _, _ = net.rpartition('.')
        try:
            import ipaddress as _ipa
            _defaddr = str(_ipa.ip_address(int(_ipa.ip_network(local, strict=False).network_address) + 1))
        except Exception:
            _defaddr = '%s.1' % a
        int_addr = '%s/%s' % (vpn_server_addr('wireguard', v) or _defaddr, m)
    else:
        int_addr = local
    port = v.get('port', 51820)
    priv = v.get('priv', '')
    run(['modprobe', 'wireguard'])
    L = ['# 由 RouteWeb 生成 (WireGuard)\n']
    L.append('[Interface]\n')
    L.append('Address = %s\n' % int_addr)
    L.append('ListenPort = %s\n' % port)
    L.append('PrivateKey = %s\n' % priv)
    # 不做 PostUp/PostDown: 本机为 nftables(无 iptables), NAT 由 apply_nft 统一生成
    # (gen_nft 会对各启用 VPN 网段 masquerade), 这里再写 iptables 规则会因
    # "iptables: command not found" 导致 wg-quick 启动失败。
    for p in v.get('peers', []):
        L.append('[Peer]\n')
        L.append('PublicKey = %s\n' % safe_file(p.get('pub', '')))
        L.append('AllowedIPs = %s\n' % safe_file(p.get('allowed', '')))
    with open('/etc/wireguard/wg0.conf', 'w') as f:
        f.write(''.join(L))

def wg_gen_keys():
    rc, out, err = run(['wg', 'genkey'])
    if rc != 0 or not out.strip():
        return None, None
    priv = out.strip()
    rc2, out2, err2 = run_in(['wg', 'pubkey'], priv)
    if rc2 != 0 or not out2.strip():
        return priv, None
    return priv, out2.strip()

# ============ VPN: 应用(生成配置 + 启停服务 + 刷新防火墙/NAT) ============
# 各协议需要由 systemd 托管的服务单元
VPN_UNITS = {
    'pptp': ['pptpd'],
    'l2tp': ['xl2tpd', 'strongswan'],
    'openvpn': ['openvpn@server'],
    'ikev2': ['strongswan'],
    'wireguard': ['wg-quick@wg0'],
}

def _svc_start(unit):
    """可靠启动: reset-failed -> enable(持久化) -> start。
    注意: pptpd/xl2tpd 为 LSB(SysV) 单元, 其 `enable --now` 会被重定向到
    systemd-sysv-install 而丢失 --now 语义, 因此必须显式 start。"""
    run(['systemctl', 'reset-failed', unit])
    run(['systemctl', 'enable', unit])
    run(['systemctl', 'start', unit])

def _svc_stop(unit):
    """可靠停止: 显式 stop + disable。
    LSB 单元的 `disable --now` 实测不会真正停止服务(rc=0 但仍 active),
    故拆成两条命令。"""
    run(['systemctl', 'stop', unit])
    run(['systemctl', 'disable', unit])

def _svc_active(unit):
    rc, out, err = run(['systemctl', 'is-active', unit])
    return out.strip() == 'active'

def start_vpn(proto):
    for u in VPN_UNITS.get(proto, []):
        _svc_start(u)

def stop_vpn(proto, state=None):
    for u in VPN_UNITS.get(proto, []):
        # L2TP 与 IKEv2 共用 strongswan: 停 L2TP 时若 IKEv2 仍启用则保留
        if (u == 'strongswan' and proto == 'l2tp' and state
                and state['vpn'].get('ikev2', {}).get('enabled')):
            continue
        _svc_stop(u)

def vpn_runtime_check(proto):
    """校验服务是否真正进入 active; 未运行则提取关键错误行, 便于前端如实提示。"""
    bad = []
    for u in VPN_UNITS.get(proto, []):
        if not _svc_active(u):
            rc, out, err = run(['systemctl', 'status', u, '--no-pager', '-n', '12'])
            txt = out or err
            keys = [ln.strip() for ln in txt.splitlines()
                    if any(k in ln for k in ('Failed', 'failed', 'Error', 'error',
                                             'Bad', 'exit-code', 'not found',
                                             'not the correct'))]
            bad.append('%s 未运行%s' % (u, (' (' + keys[-1] + ')') if keys else ''))
    return (len(bad) == 0), '; '.join(bad)

def apply_vpn(state, proto):
    v = state['vpn'][proto]
    if not v.get('enabled'):
        stop_vpn(proto, state)
        apply_nft(state)
        return 0, '', '已停用'
    # 生成配置
    pptp_changed = False
    if proto == 'pptp':
        pptp_changed = gen_pptp_files(state) is True
    elif proto == 'l2tp':
        gen_l2tp_files(state)
        gen_ipsec(state)
    elif proto == 'openvpn':
        gen_ovpn_files(state)
    elif proto == 'ikev2':
        gen_ipsec(state)
    elif proto == 'wireguard':
        gen_wg_files(state)
    start_vpn(proto)
    # pptpd 启动时才读地址池: 若服务此前已在运行, start 不会重载新配置,
    # 必须显式 restart, 否则出现"页面显示新网段、客户端仍拿到旧网段"
    # (进而因该网段无 SNAT 规则而无法上网)。
    if proto == 'pptp' and pptp_changed and _svc_active('pptpd'):
        run(['systemctl', 'restart', 'pptpd'])
    apply_nft(state)
    # 启用后校验真实服务状态: 避免"配置有误但提示成功"的假象
    ok, detail = vpn_runtime_check(proto)
    if not ok:
        return 1, '', '启动失败: ' + detail
    return 0, '', '已启用并应用'

# ============ 客户端 VPN: OpenVPN / L2TP / PPTP (网关拨入远端) ============
def next_ovpn_dev(state):
    """为 OVPN 客户端分配一个固定的 tun 设备号(tun10 起), 便于界面回显隧道地址。"""
    used = set()
    for c in state.get('ovpn_clients', []):
        d = ovpn_dev(c)
        if d:
            used.add(d)
    for n in range(10, 100):
        d = 'tun%d' % n
        if d not in used:
            return d
    return ''


def ovpn_client_conf_path(name):
    return os.path.join(OVPN_CLIENT_DIR, '%s.conf' % safe_file(name))


def gen_ovpn_client_conf(name, c):
    os.makedirs(OVPN_CLIENT_DIR, exist_ok=True)
    cf = ovpn_client_conf_path(name)
    L = []
    L.append('# 由 RouteWeb 生成 (OpenVPN 客户端: %s)' % safe_file(name))
    L.append('client')
    L.append('dev %s' % (ovpn_dev(c) or 'tun'))
    L.append('proto %s' % ('tcp' if c.get('proto') == 'tcp' else 'udp'))
    L.append('remote %s %s' % (safe_file(c.get('remote', '')), safe_file(str(c.get('port', 1194)))))
    L.append('resolv-retry infinite')
    L.append('nobind')
    L.append('persist-key')
    L.append('persist-tun')
    # 服务端证书校验: 导入的 .ovpn 若自带 remote-cert-tls / ns-cert-type 则以它为准(不重复下发)
    if not re.search(r'^\s*(remote-cert-tls|ns-cert-type)\b', (c.get('extra') or ''), re.M | re.I):
        L.append('remote-cert-tls server')
    L.append('cipher AES-256-GCM')
    L.append('auth SHA256')
    ca = c.get('ca', '').strip()
    cert = c.get('cert', '').strip()
    key = c.get('key', '').strip()
    if ca:
        L.append('<ca>\n%s\n</ca>' % ca)
    if cert:
        L.append('<cert>\n%s\n</cert>' % cert)
    if key:
        L.append('<key>\n%s\n</key>' % key)
    if c.get('user'):
        up = os.path.join(OVPN_CLIENT_DIR, '%s.up' % safe_file(name))
        with open(up, 'w') as f:
            f.write('%s\n%s\n' % (safe_file(c.get('user', '')), safe_file(c.get('pass', ''))))
        os.chmod(up, 0o600)
        L.append('auth-user-pass %s' % up)
    if c.get('redirect'):
        L.append('redirect-gateway def1')
    else:
        # 未勾选"全流量走隧道"时, 必须挡掉远端下发的默认路由:
        # 远端 push 的 redirect-gateway 会在网关主路由表里写 0.0.0.0/1 与 128.0.0.0/1,
        # 比本地 default 更长, 会把网关自身以及"拨入本网关的 VPN 客户端"的出网流量
        # 全部吸进这条隧道(而隧道方向通常没有 SNAT) -> 表现为拨号后上不了网。
        if not re.search(r'^\s*pull-filter\b', (c.get('extra') or ''), re.M | re.I):
            L.append('pull-filter ignore redirect-gateway')
    # 远端内网网段: 走隧道的静态路由
    for net in nets_of(c):
        L.append('route %s %s' % (net.split('/')[0], cidr_mask(net)))
    extra = c.get('extra', '').strip()
    if extra:
        for line in extra.split('\n'):
            line = line.strip()
            if line:
                L.append(line)
    with open(cf, 'w') as f:
        f.write('\n'.join(L) + '\n')

def ovpn_client_status(name):
    rc, out, err = run(['systemctl', 'is-active', 'openvpn-client@%s' % safe_file(name)])
    return out.strip() == 'active'

def ovpn_client_up(name):
    run(['systemctl', 'enable', '--now', 'openvpn-client@%s' % safe_file(name)])

def ovpn_client_down(name):
    run(['systemctl', 'disable', '--now', 'openvpn-client@%s' % safe_file(name)])


def ovpn_client_profile(name, c=None):
    """导出“网关作为 OpenVPN 客户端(拨号端)”的配置为可移植的 .ovpn 文本。
    去除本机路径依赖: dev 归一为 tun、auth-user-pass 改为交互式输入;
    配置文件缺失时按当前 state 现场生成后读回。"""
    c = c or {}
    cf = ovpn_client_conf_path(name)
    txt = ''
    try:
        with open(cf) as f:
            txt = f.read()
    except Exception:
        txt = ''
    if not txt.strip() and c:
        try:
            gen_ovpn_client_conf(name, c)
            with open(cf) as f:
                txt = f.read()
        except Exception:
            return ''
    if not txt.strip():
        return ''
    out = []
    for line in txt.split('\n'):
        s = line.strip()
        low = s.lower()
        if low.startswith('dev ') and not low.startswith('dev-node'):
            out.append('dev tun')
            continue
        if low.startswith('auth-user-pass '):
            out.append('auth-user-pass')
            continue
        out.append(line)
    hdr = ['# RouteWeb 导出: OpenVPN 客户端配置 (%s)' % safe_file(name),
           '# 远端服务器: %s:%s' % (c.get('remote', ''), c.get('port', '')),
           '# 已去除本机路径依赖(dev / 凭据文件), 可直接在其它 OpenVPN 客户端导入']
    return '\n'.join(hdr) + '\n' + '\n'.join(out).strip('\n') + '\n'


def dl_safe_name(s):
    """下载文件名清洗: 只保留安全字符, 杜绝路径穿越与引号注入。"""
    n = re.sub(r'[^A-Za-z0-9._-]', '_', (s or '').strip())[:64]
    return n or 'client'


def ovpn_download_payload(kind, name, mode='full'):
    """按类型生成待下载的 .ovpn 内容与文件名; 失败返回 (None, '')。
    kind='server' OpenVPN 服务端签发的客户端配置(全流量 / 仅内网)
    kind='client' 网关作为 OpenVPN 客户端的拨号配置"""
    state = load_state()
    if kind == 'client':
        c = None
        for x in state.get('ovpn_clients', []):
            if x.get('name') == name:
                c = x
                break
        if c is None:
            return None, ''
        txt = ovpn_client_profile(name, c)
        fn = '%s-client.ovpn' % dl_safe_name(name)
    else:
        names = [x.get('name') for x in state['vpn']['openvpn'].get('clients', [])]
        if name not in names:
            return None, ''
        txt = ovpn_client_conf(name, mode)
        fn = ('%s.ovpn' if mode != 'lan' else '%s-lan.ovpn') % dl_safe_name(name)
    if not txt.strip():
        return None, ''
    return txt, fn

# ---------- 导入 .ovpn 配置文件(网关作为 OpenVPN 客户端) ----------
OVPN_IMPORT_MAX = 262144          # 上传文件上限 256KB(含证书的配置通常 < 20KB)
# 引用"外部文件"的指令: 上传只带一个 .ovpn, 拿不到这些文件, 导入时丢弃并提示
OVPN_FILE_DIRECTIVES = ('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2',
                        'secret', 'askpass')
# 会在网关上执行外部程序 / 改写本地运行方式的指令: 一律丢弃(安全 + 避免与托管逻辑冲突)
OVPN_SCRIPT_DIRECTIVES = ('script-security', 'up', 'down', 'route-up', 'route-pre-down',
                          'ipchange', 'client-connect', 'client-disconnect', 'tls-verify',
                          'learn-address', 'auth-user-pass-verify', 'plugin', 'daemon',
                          'log', 'log-append', 'writepid', 'chroot', 'user', 'group',
                          'management', 'status', 'cd', 'machine-readable-output')
OVPN_INLINE_TAGS = ('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2',
                    'secret', 'extra-certs', 'pkcs12')


def parse_multipart(ctype, body):
    """极简 multipart/form-data 解析(不依赖已废弃的 cgi 模块)。

    返回 (fields, files):
      fields: {name: 文本值}
      files : {name: {'filename': 原始文件名, 'data': bytes}}
    """
    fields, files = {}, {}
    m = re.search(r'boundary=(?:"([^"]*)"|([^;]+))', ctype or '')
    if not m:
        return fields, files
    b = (m.group(1) or m.group(2) or '').strip()
    if not b:
        return fields, files
    delim = b'--' + b.encode('utf-8', 'replace')
    for part in body.split(delim):
        part = part.strip(b'\r\n')
        if not part or part == b'--':
            continue
        head, sep, data = part.partition(b'\r\n\r\n')
        if not sep:
            continue
        htxt = head.decode('utf-8', 'replace')
        nm = re.search(r'\bname="([^"]*)"', htxt)
        if not nm:
            continue
        name = nm.group(1)
        fm = re.search(r'\bfilename="([^"]*)"', htxt)
        if fm:
            files[name] = {'filename': fm.group(1), 'data': data}
        else:
            fields[name] = data.decode('utf-8', 'replace')
    return fields, files


def mask_to_cidr(ip, mask):
    """点分掩码 -> CIDR 前缀(OpenVPN 的 route 也接受 net + netmask 两段写法)。"""
    if not is_ip(ip):
        return ''
    try:
        bits = sum(bin(int(x)).count('1') for x in str(mask).split('.'))
    except Exception:
        return ''
    if bits < 0 or bits > 32:
        return ''
    return '%s/%d' % (ip, bits)


def ovpn_parse_profile(text):
    """解析 .ovpn 文本 -> 网关作为客户端所需的参数。

    策略: 远端相关、本机相关的指令分开处理——
      remote / proto / route / redirect-gateway / inline 证书 -> 转成 state 字段(界面可再编辑)
      dev / 外部文件 / 脚本类指令                              -> 丢弃并给出提示
      其余(cipher / tls-auth / verb / keepalive …)             -> 原样保留进 extra, 覆盖模板默认值
    返回 dict: remote port proto nets redirect ca cert key need_auth extra warnings dev
    """
    res = {'remote': '', 'port': '1194', 'proto': 'udp', 'nets': [], 'redirect': False,
           'ca': '', 'cert': '', 'key': '', 'need_auth': False, 'extra': '',
           'warnings': [], 'dev': ''}
    txt = (text or '').replace('\r\n', '\n').replace('\r', '\n')
    keep, routes = [], []
    inline, tag, buf = {}, None, []
    for line in txt.split('\n'):
        s = line.strip()
        if tag:                                    # 正在读内联块(结尾可能和内容挤在同一行)
            if ('</%s>' % tag) in s.lower():
                tail = s.lower().split('</%s>' % tag)[0]
                if tail:
                    buf.append(line[:len(tail)].rstrip())
                inline[tag] = '\n'.join(buf).strip()
                tag, buf = None, []
            else:
                buf.append(line.rstrip())
            continue
        if not s or s[0] in '#;':
            continue
        parts = s.split()
        cmd = parts[0].lower()
        m0 = re.match(r'^<([A-Za-z0-9_-]+)>(.*)$', s)   # 内联块起始(容忍 "<ca>-----BEGIN…" 同行写法)
        if m0:
            t = m0.group(1).lower()
            rest = m0.group(2).strip()
            if t in OVPN_INLINE_TAGS:
                if rest and ('</%s>' % t) in rest.lower():
                    inline[t] = rest.lower().split('</%s>' % t)[0].strip()
                else:
                    tag, buf = t, ([rest] if rest else [])
            else:
                res['warnings'].append('已忽略未知内联块 <%s>' % t)
            continue
        arg1 = parts[1] if len(parts) > 1 else ''
        if cmd == 'remote':                        # 第一条为主远端, 其余(备用)原样保留
            if not res['remote'] and arg1:
                res['remote'] = arg1
                if len(parts) > 2 and is_port(parts[2]):
                    res['port'] = parts[2]
            else:
                keep.append(s)
            continue
        if cmd == 'proto':                         # udp4/tcp-client 等一并归一
            if arg1.lower().startswith('tcp'):
                res['proto'] = 'tcp'
            elif arg1.lower().startswith('udp'):
                res['proto'] = 'udp'
            continue
        if cmd == 'dev':                           # 设备名由网关统一分配(tun10 起)
            res['dev'] = arg1.lower()
            if res['dev'].startswith('tap'):
                res['warnings'].append('原配置为 tap(二层)设备，已按 tun(三层)导入')
            continue
        if cmd == 'route':
            if arg1.lower() in ('0.0.0.0', '128.0.0.0', 'default'):
                continue                           # redirect-gateway def1 的等价写法
            net = arg1
            if len(parts) > 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[2]):
                net = mask_to_cidr(net, parts[2])  # route net netmask [gw]
            if is_cidr(net):
                if net not in routes:
                    routes.append(net)
            else:
                res['warnings'].append('已忽略无法识别的 route: %s' % s)
            continue
        if cmd == 'redirect-gateway':
            res['redirect'] = True
            continue
        if cmd == 'auth-user-pass':                # 凭据表单里填
            res['need_auth'] = True
            continue
        if cmd == 'pkcs12':
            res['warnings'].append('不支持 PKCS#12 打包配置，请改用 ca / cert / key 分离的形式')
            continue
        if cmd in OVPN_FILE_DIRECTIVES:
            res['warnings'].append('配置引用了外部文件（%s），导入后需在“修改”里粘贴其内容' % s)
            continue
        if cmd in OVPN_SCRIPT_DIRECTIVES:
            res['warnings'].append('已忽略本地/脚本类指令: %s' % cmd)
            continue
        keep.append(s)
    for t in ('ca', 'cert', 'key'):
        res[t] = inline.get(t, '')
    for t in ('tls-auth', 'tls-crypt', 'tls-crypt-v2', 'secret', 'extra-certs'):
        v = inline.get(t)
        if not v:
            continue
        if t == 'tls-auth' and not any(x.lower().startswith('key-direction') for x in keep):
            keep.append('key-direction 1')
        keep.append('<%s>\n%s\n</%s>' % (t, v, t))
    if inline.get('pkcs12'):
        res['warnings'].append('不支持内联 PKCS#12，请改用 ca / cert / key 分离的形式')
    if not res['ca']:
        res['warnings'].append('未发现 CA 证书（无 <ca> 内联块），需在“修改”里粘贴 CA')
    if not (res['cert'] and res['key']) and not res['need_auth']:
        res['warnings'].append('既无客户端证书也无 auth-user-pass，可能无法通过服务端认证')
    res['nets'] = routes
    res['extra'] = '\n'.join(keep).strip()
    return res


def ovpn_import_check(name, state=None):
    """导入前校验名称: 合法性 + 重名。返回错误信息, 通过返回 ''。"""
    if not re.match(r'^[A-Za-z0-9_.-]{1,32}$', name or ''):
        return '名称非法（1-32 位，仅字母数字 . _ -）'
    for c in (state or load_state()).get('ovpn_clients', []):
        if c.get('name') == name:
            return '名称“%s”已存在，请换一个或用“修改”覆盖配置' % name
    return ''


def ovpn_import_name(gname, filename):
    """导入时的名称: 表单优先, 其次取文件名主干(清洗为安全字符)。"""
    n = (gname or '').strip()
    if not n:
        base = os.path.basename((filename or '').strip())
        n = re.sub(r'\.(ovpn|conf|txt)$', '', base, flags=re.I)
        n = re.sub(r'[^A-Za-z0-9_.-]', '-', n).strip('-')[:32]
    return n


def ovpn_import_client(name, p, user='', pw='', nets=None, state=None, src=''):
    """按解析结果落地一个 OpenVPN 客户端。返回 (dict, 错误消息)。"""
    st = state or load_state()
    err = ovpn_import_check(name, st)
    if err:
        return None, err
    if not p.get('remote'):
        return None, '配置文件里没有 remote 指令（不是有效的客户端 .ovpn？）'
    ns = nets if nets else [x for x in p.get('nets', []) if is_cidr(x)]
    c = {'name': name, 'remote': safe_file(p.get('remote', '')),
         'port': p.get('port', '1194') or '1194',
         'proto': 'tcp' if p.get('proto') == 'tcp' else 'udp',
         'dev': next_ovpn_dev(st), 'nets': ns,
         'user': user, 'pass': pw,
         'ca': p.get('ca', ''), 'cert': p.get('cert', ''), 'key': p.get('key', ''),
         'redirect': bool(p.get('redirect')),
         'extra': p.get('extra', ''), 'src': src,
         'imported': time.strftime('%Y-%m-%d %H:%M')}
    st.setdefault('ovpn_clients', []).append(c)
    save_state(st)
    gen_ovpn_client_conf(name, c)
    write_nets_file(name, ns)
    return c, ''


# ---- PPP 客户端日志与进程识别 ----
PPP_LOG_DIR = '/var/log/routeweb-ppp'


def ppp_log(name):
    return os.path.join(PPP_LOG_DIR, safe_file(name) + '.log')


def ppp_reset_log(name):
    """每次拨号/断开前清空日志, 让界面上的失败原因只反映本次拨号。"""
    try:
        os.makedirs(PPP_LOG_DIR, exist_ok=True)
        open(ppp_log(name), 'w').close()
    except Exception:
        pass


def ppp_procs():
    """扫描 /proc 找出正在运行的 pppd, 返回 {ipparam/链路名: pid}。

    不能用 `pgrep -f "pppd.*call X"`: 该模式会匹配到执行 pgrep 的
    bash 自身(它的命令行里就含这段文字), 导致"未连接也显示已连接"。
    """
    res = {}
    try:
        pids = os.listdir('/proc')
    except Exception:
        return res
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            with open('/proc/%s/cmdline' % pid, 'rb') as f:
                parts = [x.decode('utf-8', 'replace') for x in f.read().split(b'\0') if x]
        except Exception:
            continue
        if not parts or not os.path.basename(parts[0]).startswith('pppd'):
            continue
        key = ''
        for i, a in enumerate(parts):
            if a in ('ipparam', 'call') and i + 1 < len(parts):
                key = parts[i + 1]
                break
            m = re.search(r'options\.l2tp-(\S+)$', a)
            if m:
                key = m.group(1)
                break
        if key:
            res[safe_file(key)] = int(pid)
    return res


PPP_ERR_PAT = (
    ('bad username or password', '认证失败：账号或密码错误'),
    ('authentication failed', '认证失败：账号或密码错误'),
    ('no suitable secret', '认证参数配置错误'),
    ('mppe', 'MPPE 加密协商失败（对端不支持或缺少 ppp_mppe 模块）'),
    ('peer is not responding', '对端无响应'),
    ('timeout sending config-requests', '对端无响应（LCP 超时）'),
    ('connection refused', '对端拒绝连接（1723 未开放）'),
    ('no route to host', '无法到达服务器（路由/防火墙拦截）'),
    ('modem hangup', '链路被对端断开'),
    ('gre:', 'GRE 隧道异常（47 协议被拦截）'),
)


def ppp_err(name):
    """从 pppd 日志提取本次拨号的失败原因。

    日志在每次拨号/断开前都会被清空, 所以文件内容只覆盖本次会话;
    persist 反复重试只会追加同样的失败行, 因此整文件从尾向前找一次即可,
    结果稳定不会随轮询闪烁。
    """
    p = ppp_log(name)
    try:
        if os.path.getsize(p) > 400000:
            return ''
        with open(p, 'r', errors='replace') as f:
            lines = [x.strip() for x in f.read().splitlines() if x.strip()]
    except Exception:
        return ''
    for line in reversed(lines):
        low = line.lower()
        for pat, msg in PPP_ERR_PAT:
            if pat in low:
                return msg
    return ''


def gen_pptp_client_peer(name, c):
    os.makedirs('/etc/ppp/peers', exist_ok=True)
    os.makedirs(PPP_LOG_DIR, exist_ok=True)
    pf = '/etc/ppp/peers/%s' % safe_file(name)
    L = []
    L.append('# 由 RouteWeb 生成 (PPTP 客户端: %s)' % safe_file(name))
    L.append('pty "pptp %s --nolaunchpppd"' % safe_file(c.get('server', '')))
    L.append('name %s' % safe_file(c.get('user', '')))
    L.append('remotename %s' % safe_file(name))
    L.append('ipparam %s' % safe_file(name))
    L.append('password %s' % safe_file(c.get('pass', '')))
    # 客户端语义: 由对端认证"我们", 所以必须 noauth(不要求对端自证)。
    # 切勿使用 require-mschap-v2/require-chap —— 那是服务端语义, 会让 pppd
    # 在启动阶段就要求对端出示密码并以 "remote system is required to
    # authenticate itself" 直接退出, 造成永远拨不通、界面无任何隧道数据。
    L.append('noauth')
    L.append('refuse-pap')
    L.append('refuse-eap')
    L.append('refuse-chap')
    L.append('refuse-mschap')
    L.append('require-mppe-128')
    if c.get('defaultroute'):
        L.append('defaultroute')
    else:
        L.append('nodefaultroute')
    L.append('usepeerdns')
    L.append('persist')
    L.append('maxfail 0')
    L.append('mtu 1400')
    L.append('mru 1400')
    L.append('nobsdcomp')
    L.append('nodeflate')
    L.append('hide-password')
    L.append('debug')
    L.append('logfile %s' % ppp_log(name))
    with open(pf, 'w') as f:
        f.write('\n'.join(L) + '\n')
    write_nets_file(name, nets_of(c))

def pptp_client_status(name):
    """pppd 是否在用 ipparam=<name> 运行(拨号中或已连接)。"""
    return safe_file(name) in ppp_procs()

def pptp_client_up(name):
    ppp_reset_log(name)
    run(['pon', safe_file(name)])

def wait_ppp_gone(name, secs=4):
    """等待某条 PPP 链路进程退出(避免手动断开后残留日志被当成故障原因)。"""
    for _ in range(int(secs * 5)):
        if safe_file(name) not in ppp_procs():
            return True
        time.sleep(0.2)
    return False


def pptp_client_down(name):
    run(['poff', safe_file(name)])
    wait_ppp_gone(name)
    # poff 只能结束 pppd; pppd 异常退出时 ip-down 钩子不触发, 隧道记录会残留,
    # 界面会一直显示"已连接"。这里显式清理, 保证"停用"一定生效。
    clear_tun_record(name)
    ppp_reset_log(name)

def l2tp_client_status(name):
    """pppd 是否在用 ipparam=<name> 运行(由 xl2tpd 拉起)。"""
    return safe_file(name) in ppp_procs()

def l2tp_client_up(name):
    ppp_reset_log(name)
    run(['systemctl', 'restart', 'xl2tpd'])

def l2tp_client_down(name):
    run(['systemctl', 'stop', 'xl2tpd'])
    wait_ppp_gone(name)
    clear_tun_record(name)
    ppp_reset_log(name)

# ---- 隧道运行信息: 接口 / 隧道 IP / 对端 / 速率 ----
TUN_DIR = '/run/routeweb/tun'
# 各客户端需要走隧道的"远端内网网段", 钩子(ip-up)据此下发路由
NETS_DIR = '/etc/routeweb/nets'


def norm_nets(s):
    """把用户输入的网段串规范化为 CIDR 列表。非法项抛 ValueError(便于回显)。"""
    out = []
    for x in re.split(r'[,\s]+', (s or '').strip()):
        if not x:
            continue
        if not is_cidr(x):
            raise ValueError(x)
        if x not in out:
            out.append(x)
    return out


def nets_of(c):
    """读取客户端配置中的远端网段列表(兼容历史上没有该字段的配置)。"""
    v = c.get('nets')
    if isinstance(v, list):
        return [x for x in v if is_cidr(x)]
    if isinstance(v, str):
        try:
            return norm_nets(v)
        except ValueError:
            return []
    return []


def nets_text(c):
    return ', '.join(nets_of(c))


def cidr_mask(c):
    """CIDR 前缀 -> 点分掩码(OpenVPN 的 route 指令需要 net + netmask 两段)。"""
    try:
        n = max(0, min(32, int(str(c).split('/')[1])))
    except Exception:
        n = 32
    bits = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
    return '.'.join(str((bits >> s) & 0xFF) for s in (24, 16, 8, 0))


def ovpn_push_routes(state):
    """OpenVPN 服务端要 push 给客户端的路由网段(CIDR 列表)。

    组成: 内网网段(可关) + 出向隧道的远端网段(可选) + 自定义网段。
    已去重、按网络地址规范化; 非法项直接丢弃(不抛异常, 保证配置生成不被打断)。
    """
    v = (state.get('vpn', {}).get('openvpn') or {})
    out = []

    def _add(x):
        x = (x or '').strip()
        if not x:
            return
        if not is_cidr(x):
            parts = x.split()
            # 兼容 "10.10.2.0 255.255.255.0" 与单个 IP 两种写法
            if len(parts) == 2:
                x = mask_to_cidr(parts[0], parts[1])
            elif len(parts) == 1 and is_ip(parts[0]):
                x = parts[0] + '/32'
            else:
                return
        if not is_cidr(x):
            return
        try:
            import ipaddress as _ip
            s = str(_ip.ip_network(x, strict=False))
        except Exception:
            return
        if s not in out:
            out.append(s)

    if v.get('push_lan', True):
        _add(LAN_NET)
    if v.get('push_tunnels'):
        for key in ('ovpn_clients', 'pptp_clients', 'l2tp_clients'):
            for c in (state.get(key) or []):
                for n in nets_of(c):
                    _add(n)
    for n in (v.get('push_routes') or []):
        _add(n)
    return out


def ovpn_push_default(state):
    """是否让客户端全流量走隧道(push redirect-gateway def1)。缺省为 True(保持历史行为)。"""
    v = (state.get('vpn', {}).get('openvpn') or {})
    return bool(v.get('push_default', True))


def write_nets_file(name, nets):
    """写 /etc/routeweb/nets/<客户端名>, 每行一个 CIDR, 供 pppd ip-up 钩子读取。"""
    try:
        os.makedirs(NETS_DIR, exist_ok=True)
        p = os.path.join(NETS_DIR, safe_file(name))
        if not nets:
            if os.path.exists(p):
                os.remove(p)
            return
        txt = '\n'.join(nets) + '\n'
        cur = ''
        if os.path.exists(p):
            with open(p) as f:
                cur = f.read()
        if cur != txt:
            with open(p, 'w') as f:
                f.write(txt)
    except Exception:
        pass


def apply_client_routes(name, nets):
    """客户端已连接时立即补下路由, 免去重拨。返回实际下发的网段数。"""
    rec = tun_record(name)
    if not rec or not nets:
        return 0
    iface, peer = rec.get('iface', ''), rec.get('peer', '')
    if not (iface and peer):
        return 0
    n = 0
    for net in nets:
        rc, out, err = run(['ip', 'route', 'replace', net, 'via', peer, 'dev', iface])
        if rc == 0:
            n += 1
    return n

PPP_UP_HOOK = """#!/bin/sh
# 由 RouteWeb 自动生成: 记录 PPP 会话(服务端接入/客户端拨号) + 隧道地址 + 下发"远端网段"路由
mkdir -p %s 2>/dev/null
# --- 会话记录: 供"在线客户端 / 连接历史"展示 ---
_P=$PPID; _i=0; _C=
while [ "$_i" -lt 5 ]; do
  _C=$(cat /proc/$_P/comm 2>/dev/null) || _C=
  [ "$_C" = "pppd" ] && break
  _P=$(awk '{print $4}' /proc/$_P/stat 2>/dev/null)
  case "$_P" in ''|*[!0-9]*) break ;; esac
  _i=$((_i+1))
done
_GP=; _GN=
if [ "$_C" = "pppd" ]; then
  _GP=$(awk '{print $4}' /proc/$_P/stat 2>/dev/null)
  [ -n "$_GP" ] && _GN=$(cat /proc/$_GP/comm 2>/dev/null)
fi
# pptpd 的链路进程树: pptpd -> pptpctrl -> pppd; xl2tpd 的: xl2tpd -> pppd
case "${_GN}" in pptpctrl|pptpd|xl2tpd) _KEY="srv-$PPP_IFACE" ;; *) _KEY="${PPP_IPPARAM:-cli-$PPP_IFACE}" ;; esac
printf 'iface=%%s\\nlocal=%%s\\nremote=%%s\\nsince=%%s\\nuser=%%s\\npeerlog=%%s\\nipparam=%%s\\npid=%%s\\nppid=%%s\\ndaemon=%%s\\n' \
    "$PPP_IFACE" "$PPP_LOCAL" "$PPP_REMOTE" "$(date +%%s)" "${PEERNAME:-}" "${PPPLOGNAME:-}" \
    "$PPP_IPPARAM" "${_P:-}" "${_GP:-}" "${_GN:-}" > "%s/ppp-$_KEY" 2>/dev/null
[ -n "$PPP_IPPARAM" ] || exit 0
mkdir -p %s 2>/dev/null || exit 0
printf '%%s\\n%%s\\n%%s\\n%%s\\n' "$PPP_IFACE" "$PPP_LOCAL" "$PPP_REMOTE" "$(date +%%s)" \
    > "%s/$PPP_IPPARAM" 2>/dev/null
# 远端内网网段(每行一个 CIDR): 下一跳为 PPP 对端, 出接口为本隧道
NF="%s/$PPP_IPPARAM"
if [ -f "$NF" ]; then
    while read -r net; do
        case "$net" in ""|\\#*) continue ;; esac
        ip route replace "$net" via "$PPP_REMOTE" dev "$PPP_IFACE" 2>/dev/null
    done < "$NF"
fi
exit 0
"""

PPP_DOWN_HOOK = """#!/bin/sh
# 由 RouteWeb 自动生成: 隧道断开时清理记录、写连接历史、撤销远端网段路由
_KEY="$PPP_IPPARAM"; [ -n "$_KEY" ] || _KEY="srv-$PPP_IFACE"
_SF="%s/ppp-$_KEY"
if [ ! -f "$_SF" ]; then _SF="%s/ppp-srv-$PPP_IFACE"; fi
if [ -f "$_SF" ]; then
  _g(){ sed -n "s/^$1=//p" "$_SF" | head -1; }
  _D=$(_g daemon)
  case "$_D" in pptpctrl|pptpd|xl2tpd) _SRV=1 ;; *) _SRV=0 ;; esac
  if [ "$_SRV" = 1 ]; then
  _RX=$(cat /sys/class/net/$PPP_IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
  _TX=$(cat /sys/class/net/$PPP_IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  _S=$(_g since); _U=$(_g user); _R=$(_g remote)
  # pptpd 把 ipparam 设为客户端公网 IP, 可直接作为来源地址
  _SRC="$PPP_IPPARAM"; case "$_SRC" in *[!0-9.]*) _SRC= ;; esac
  case "$_D" in xl2tpd) _PR=l2tp ;; *) _PR=pptp ;; esac
  _NOW=$(date +%%s); _DUR=0
  case "$_S" in ''|*[!0-9]*) _S=0 ;; *) _DUR=$(( _NOW - _S )) ;; esac
  printf '%%s\\t%%s\\t%%s\\t%%s\\t%%s\\t%%s\\t%%s\\t%%s\\t%%s\\n' \
      "$_NOW" "$_PR" "${_U:--}" "${_SRC:--}" "${_R:--}" "$_S" "$_DUR" "$_RX" "$_TX" \
      >> "%s" 2>/dev/null
  fi
fi
rm -f "$_SF" 2>/dev/null
[ -n "$PPP_IPPARAM" ] || exit 0
rm -f "%s/$PPP_IPPARAM" 2>/dev/null
NF="%s/$PPP_IPPARAM"
if [ -f "$NF" ]; then
    while read -r net; do
        case "$net" in ""|\\#*) continue ;; esac
        ip route del "$net" dev "$PPP_IFACE" 2>/dev/null
    done < "$NF"
fi
exit 0
"""


def ensure_ppp_hooks():
    """幂等安装 pppd 的 ip-up/ip-down 钩子。

    pppd 通过环境变量 PPP_IPPARAM(= 我们写入的 ipparam <客户端名>) 标识链路,
    钩子把 接口名/本端IP/对端IP/建立时间 落到 /run/routeweb/tun/<名称>。
    """
    try:
        for d in ('/etc/ppp/ip-up.d', '/etc/ppp/ip-down.d', PPP_LOG_DIR):
            os.makedirs(d, exist_ok=True)
        os.makedirs(TUN_DIR, exist_ok=True)
        os.makedirs(NETS_DIR, exist_ok=True)
        os.makedirs(SESS_DIR, exist_ok=True)
        try:
            with open(SESS_LOG, 'a'):
                pass
        except Exception:
            pass
    except Exception:
        return
    for path, txt in (('/etc/ppp/ip-up.d/routeweb-tunnel',
                       PPP_UP_HOOK % (SESS_DIR, SESS_DIR, TUN_DIR, TUN_DIR, NETS_DIR)),
                      ('/etc/ppp/ip-down.d/routeweb-tunnel',
                       PPP_DOWN_HOOK % (SESS_DIR, SESS_DIR, SESS_LOG, TUN_DIR, NETS_DIR))):
        try:
            cur = ''
            if os.path.exists(path):
                with open(path) as f:
                    cur = f.read()
            if cur != txt:
                with open(path, 'w') as f:
                    f.write(txt)
            os.chmod(path, 0o755)
        except Exception:
            pass


def p2p_ifaces():
    """解析 `ip -o -4 addr`, 返回隧道类接口 {iface: {'local':.., 'peer':..}}。"""
    rc, out, err = run(['ip', '-o', '-4', 'addr', 'show'])
    res = {}
    if rc != 0:
        return res
    for line in out.splitlines():
        m = re.match(r'^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?'
                     r'(?:\s+peer\s+(\d+\.\d+\.\d+\.\d+))?', line)
        if not m:
            continue
        name, local, peer = m.group(1), m.group(2), m.group(3) or ''
        if not (name.startswith('ppp') or name.startswith('tun') or name.startswith('tap')):
            continue
        res[name] = {'local': local, 'peer': peer}
    return res


def is_tunnel_if(name):
    return (name or '').startswith(('ppp', 'tun', 'tap', 'wg'))


def local_v4():
    """返回本机所有 IPv4 地址: [{'iface','addr','prefixlen','peer'}]。"""
    rc, out, err = run(['ip', '-o', '-4', 'addr', 'show'])
    res = []
    if rc != 0:
        return res
    for line in out.splitlines():
        m = re.match(r'^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)'
                     r'(?:\s+peer\s+(\d+\.\d+\.\d+\.\d+))?', line)
        if not m:
            continue
        res.append({'iface': m.group(1), 'addr': m.group(2),
                    'prefixlen': int(m.group(3)), 'peer': m.group(4) or ''})
    return res


def ip2int(ip):
    try:
        p = [int(x) for x in ip.split('.')]
    except Exception:
        return None
    if len(p) != 4 or any(x < 0 or x > 255 for x in p):
        return None
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]


def ip_in_cidr(ip, cidr):
    n = ip2int(ip or '')
    if n is None or not is_cidr(cidr or ''):
        return False
    a, _, m = cidr.partition('/')
    net = ip2int(a)
    bits = int(m)
    if net is None:
        return False
    if bits == 0:
        return True
    mask = ((1 << bits) - 1) << (32 - bits)
    return (n & mask) == (net & mask)


def tunnel_routes():
    """返回经由隧道接口的 IPv4 路由网段 [(cidr, dev)]，用于放行 Web 登录来源。"""
    rc, out, err = run(['ip', '-o', '-4', 'route', 'show'])
    res = []
    if rc != 0:
        return res
    for line in out.splitlines():
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+)', line)
        if not m or not is_tunnel_if(m.group(2)):
            continue
        # 跳过 /0-/7 超宽路由: 全流量模式(0.0.0.0/1 + 128.0.0.0/1)不应把半个互联网加入白名单
        if is_cidr(m.group(1)) and int(m.group(1).split('/')[1]) >= 8:
            res.append((m.group(1), m.group(2)))
    return res


def web_access_cfg(state=None):
    state = state if state is not None else load_state()
    wa = state.get('web_access') or {}
    return {'vpn': bool(wa.get('vpn', True)), 'extra': wa.get('extra', '') or ''}


def web_allowed_sources(state=None):
    """允许登录 Web 的来源网段 [(cidr, 说明)]。

    默认: 内网 LAN。开启 VPN 访问后追加: 各隧道接口本端地址(/32)、
    对端地址(/32) 及其所在 /24 —— 远端网络常以同段其它地址发起访问。
    """
    src = [(LAN_NET, '内网 LAN')]
    cfg = web_access_cfg(state)
    if cfg['vpn']:
        for name, info in sorted(p2p_ifaces().items()):
            if info.get('local'):
                src.append((info['local'] + '/32', '%s 本端' % name))
            if info.get('peer'):
                src.append((info['peer'] + '/32', '%s 对端' % name))
        for net, dev in tunnel_routes():
            src.append((net, '%s 路由' % dev))
    for c in re.split(r'[,\s]+', cfg['extra']):
        if is_cidr(c):
            src.append((c, '自定义'))
    return src


def norm_ip(ip):
    ip = (ip or '').strip()
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    return ip


def source_allowed(ip, state=None):
    ip = norm_ip(ip)
    if not ip or ip in ('127.0.0.1', '::1') or ip.startswith('127.'):
        return True
    for c, _ in web_allowed_sources(state):
        if ip_in_cidr(ip, c):
            return True
    return False


def tun_record(name):
    """读取某个 PPP 客户端由钩子写入的隧道记录。"""
    try:
        with open(os.path.join(TUN_DIR, safe_file(name))) as f:
            lines = [x.strip() for x in f.read().splitlines()]
        if len(lines) >= 3 and lines[0]:
            since = int(lines[3]) if len(lines) > 3 and lines[3].isdigit() else 0
            return {'iface': lines[0], 'local': lines[1], 'peer': lines[2], 'since': since}
    except Exception:
        pass
    return None


def clear_tun_record(name):
    """删除隧道记录。pppd 异常退出时 ip-down 钩子不触发, 记录会残留。"""
    try:
        os.remove(os.path.join(TUN_DIR, safe_file(name)))
        return True
    except Exception:
        return False


SINCE_DIR = '/run/routeweb/since'


def tun_since(key, live):
    """隧道在线起始时间: 首次观测到隧道在线时落盘, 断线即清除。"""
    p = os.path.join(SINCE_DIR, safe_file(key))
    if not live:
        try:
            os.remove(p)
        except Exception:
            pass
        return 0
    try:
        with open(p) as f:
            v = int((f.read() or '0').strip() or 0)
        if v > 0:
            return v
    except Exception:
        pass
    try:
        os.makedirs(SINCE_DIR, exist_ok=True)
        ts = int(time.time())
        with open(p, 'w') as f:
            f.write(str(ts))
        return ts
    except Exception:
        return 0


def ovpn_dev(c):
    """OVPN 客户端固定 tun 设备名(便于把接口和客户端一一对应)。"""
    dev = (c.get('dev') or '').strip()
    if re.match(r'^tun\d{1,3}$', dev):
        return dev
    return ''


def client_runtime(state=None):
    """汇总三类客户端的实时隧道信息: {(kind, idx): {...}}。"""
    st = state or load_state()
    stats = if_stats()
    ifs = p2p_ifaces()
    procs = ppp_procs()
    out = {}
    claimed = set()
    pending_ppp = []
    for kind, key in (('ovpn', 'ovpn_clients'), ('l2tp', 'l2tp_clients'), ('pptp', 'pptp_clients')):
        for i, c in enumerate(st.get(key, [])):
            name = c.get('name', '')
            iface, rec = '', None
            if kind == 'ovpn':
                iface = ovpn_dev(c)
            else:
                rec = tun_record(name)
                if rec:
                    iface = rec.get('iface', '')
                    # 记录里的接口已不存在(pppd 异常退出、ip-down 未触发) -> 陈旧记录,
                    # 不清理会让界面永远显示"已连接"、点"停用"也没反应
                    if iface and iface not in ifs:
                        clear_tun_record(name)
                        rec, iface = None, ''
            if iface:
                claimed.add(iface)
            else:
                pending_ppp.append((kind, i, c, name))
            out[(kind, i)] = {'name': name, 'iface': iface, 'rec': rec,
                              'on': False, 'ip': '', 'peer': '', 'rx': 0, 'tx': 0,
                              'rxr': 0.0, 'txr': 0.0, 'since': 0, 'up': 0, 'live': False,
                              'dialing': False, 'err': ''}
    # 钩子缺失时的兜底: 仅剩一个未被占用的 ppp 接口且只有一个待匹配 PPP 客户端
    free_ppp = [n for n in ifs if n.startswith('ppp') and n not in claimed]
    if len(pending_ppp) == 1 and len(free_ppp) == 1:
        kind, i, c, name = pending_ppp[0]
        out[(kind, i)]['iface'] = free_ppp[0]
    for (kind, i), r in out.items():
        iface = r.get('iface') or ''
        info = ifs.get(iface) or {}
        s = stats.get(iface) or {}
        rec = r.get('rec') or {}
        name = r.get('name', '')
        local = rec.get('local') or info.get('local') or ''
        peer = rec.get('peer') or info.get('peer') or ''
        since = rec.get('since') or 0
        f_since = tun_since('%s-%s' % (kind, name), bool(local))
        if not since:
            since = f_since
        r.update({
            'ip': local or '', 'peer': peer or '',
            'rx': int(s.get('rx_bytes', 0)), 'tx': int(s.get('tx_bytes', 0)),
            'rxr': round(float(s.get('rx_rate', 0.0)), 1),
            'txr': round(float(s.get('tx_rate', 0.0)), 1),
            'since': since,
            'up': int(time.time() - since) if since else 0,
            'live': bool(local),
        })
        if kind == 'ovpn':
            try:
                r['on'] = bool(local) or bool(ovpn_client_status(name))
            except Exception:
                r['on'] = bool(local)
        else:
            # PPP 类: 只有真正拿到隧道地址才算"已连接", 避免拨号中/认证失败误报
            r['on'] = bool(local)
            if r['on']:
                r['err'] = ''
            else:
                # 有失败原因时优先显示原因(pppd persist 会一直重试, 不能一直装作"连接中")
                r['err'] = ppp_err(name)
                r['dialing'] = (not r['err']) and (safe_file(name) in procs)
    return out


def client_info_payload():
    st = load_state()
    rt = client_runtime(st)
    rows = []
    for kind, key in (('ovpn', 'ovpn_clients'), ('l2tp', 'l2tp_clients'), ('pptp', 'pptp_clients')):
        for i, c in enumerate(st.get(key, [])):
            r = rt.get((kind, i)) or {}
            rows.append({'kind': kind, 'idx': i, 'name': c.get('name', ''),
                         'on': bool(r.get('on')), 'dialing': bool(r.get('dialing')),
                         'err': r.get('err', ''),
                         'iface': r.get('iface', ''), 'ip': r.get('ip', ''),
                         'peer': r.get('peer', ''), 'rx': r.get('rx', 0), 'tx': r.get('tx', 0),
                         'rxr': r.get('rxr', 0.0), 'txr': r.get('txr', 0.0),
                         'since': r.get('since', 0), 'up': r.get('up', 0)})
    return {'ts': round(time.time(), 3), 'clients': rows}


# ============ 网络工具: ping / 路由跟踪 ============
def is_target(s):
    """目标地址校验: 仅允许 IP 或域名, 禁止出现任何 shell 元字符/选项前缀。"""
    s = (s or '').strip()
    if not s or len(s) > 253:
        return False
    if not re.match(r'^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$', s):
        return False
    if '..' in s:
        return False
    return True


def run_cap(args, timeout=40):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, '', '命令执行超时(%ds)' % timeout
    except Exception as e:
        return -1, '', str(e)


def run_net_tool(tool, target, count='4', hops='15'):
    """执行网络诊断命令(参数以列表传递, 不做 shell 解释)。"""
    tgt = (target or '').strip()
    if not is_target(tgt):
        return '目标地址非法：仅支持 IPv4 / 域名'
    if tool == 'ping':
        try:
            n = max(1, min(20, int(count)))
        except Exception:
            n = 4
        rc, out, err = run_cap(['ping', '-n', '-c', str(n), '-W', '2', tgt], 45)
        head = 'ping %s (-c %d)' % (tgt, n)
    elif tool == 'trace':
        try:
            h = max(1, min(30, int(hops)))
        except Exception:
            h = 15
        if not os.path.exists('/usr/sbin/traceroute') and not os.path.exists('/usr/bin/traceroute'):
            return '未安装 traceroute，请先执行: apt-get install -y traceroute'
        rc, out, err = run_cap(['traceroute', '-n', '-w', '2', '-q', '1', '-m', str(h), tgt], 150)
        head = 'traceroute %s (-m %d)' % (tgt, h)
    else:
        return '未知工具'
    body = (out or '').strip()
    e = (err or '').strip()
    if e and not body:
        body = e
    elif e:
        body = body + '\n' + e
    if not body:
        body = '(无输出)'
    return '$ %s\n%s' % (head, body)


# ============ 数据收集 ============
def get_interfaces():
    rc, out, err = run(['ip', '-br', 'addr'])
    return out if rc == 0 else err

def get_routes():
    rc, out, err = run(['ip', 'route'])
    return out if rc == 0 else err

def get_ip_forward():
    try:
        with open('/proc/sys/net/ipv4/ip_forward') as f:
            return f.read().strip()
    except Exception:
        return '?'

def get_service_status(name):
    rc, out, err = run(['systemctl', 'is-active', name])
    return out.strip() or 'unknown'

def get_nat_rules():
    rc, out, err = run(['nft', 'list', 'ruleset'])
    if rc != 0:
        return err
    # 流量统计表规则较多, 展示时略去
    return re.sub(r'\ntable inet acct \{.*?\n\}\n', '\n', out, flags=re.S)

def get_leases():
    rows = []
    if os.path.exists(LEASE_FILE):
        try:
            with open(LEASE_FILE) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        rows.append({'mac': parts[1], 'ip': parts[2], 'name': parts[3] if len(parts) > 3 else '-'})
        except Exception:
            pass
    return rows

# ============ 流量监视 ============
_METRICS_LOCK = threading.Lock()
_IF_SNAP = {'ts': 0.0, 'data': {}, 'rates': {}, 'dt': 0.0}
_ACCT_SNAP = {'ts': 0.0, 'data': {}, 'rates': {}}


def read_if_counters():
    """读取 /proc/net/dev 的接口收发字节。"""
    res = {}
    try:
        with open('/proc/net/dev') as f:
            lines = f.readlines()[2:]
    except Exception:
        return res
    for line in lines:
        if ':' not in line:
            continue
        name, rest = line.split(':', 1)
        f8 = rest.split()
        if len(f8) < 10:
            continue
        try:
            res[name.strip()] = {'rx_bytes': int(f8[0]), 'rx_pkts': int(f8[1]),
                                 'tx_bytes': int(f8[8]), 'tx_pkts': int(f8[9])}
        except Exception:
            continue
    return res


def if_stats():
    """接口累计字节 + 速率(基于上次采样差值)。"""
    now = time.time()
    cur = read_if_counters()
    with _METRICS_LOCK:
        prev, pts = _IF_SNAP['data'], _IF_SNAP['ts']
        dt = now - pts
        if prev and dt >= 0.4:
            rates = {}
            for name, v in cur.items():
                p = prev.get(name) or {}
                rates[name] = {
                    'rx': max(0.0, (v['rx_bytes'] - p.get('rx_bytes', v['rx_bytes'])) / dt),
                    'tx': max(0.0, (v['tx_bytes'] - p.get('tx_bytes', v['tx_bytes'])) / dt),
                }
            _IF_SNAP['rates'] = rates
        else:
            # 间隔过短(如页面渲染与首次轮询挨着)沿用上次速率, 但基线仍刷新
            rates = dict(_IF_SNAP['rates'])
        _IF_SNAP['data'] = cur
        _IF_SNAP['ts'] = now
    out = {}
    for name, v in cur.items():
        r = rates.get(name) or {}
        out[name] = {'rx_bytes': v['rx_bytes'], 'tx_bytes': v['tx_bytes'],
                     'rx_rate': r.get('rx', 0.0), 'tx_rate': r.get('tx', 0.0)}
    return out


def get_nft_counters(table):
    """读取指定 nft 表内的命名计数器: {name: {packets, bytes}}"""
    rc, out, err = run(['nft', '-j', 'list', 'table', 'inet', table])
    res = {}
    if rc != 0:
        return res
    try:
        doc = json.loads(out)
    except Exception:
        return res
    for item in doc.get('nftables', []):
        c = item.get('counter')
        if isinstance(c, dict) and c.get('name'):
            try:
                res[c['name']] = {'packets': int(c.get('packets', 0)),
                                  'bytes': int(c.get('bytes', 0))}
            except Exception:
                continue
    return res


def acct_stats():
    """按流量类型汇总: 返回 (rows, 总字节)。"""
    now = time.time()
    cur = get_nft_counters('acct')
    if not cur:
        # 统计表被外部清掉(如 systemctl restart nftables)时自动重建
        ensure_acct()
        cur = get_nft_counters('acct')
    with _METRICS_LOCK:
        prev, pts = _ACCT_SNAP['data'], _ACCT_SNAP['ts']
        dt = now - pts
        if prev and dt >= 0.4:
            rates = {}
            for k, v in cur.items():
                pb = (prev.get(k) or {}).get('bytes', v['bytes'])
                rates[k] = max(0.0, (v['bytes'] - pb) / dt)
            _ACCT_SNAP['rates'] = rates
        else:
            rates = dict(_ACCT_SNAP['rates'])
        _ACCT_SNAP['data'] = cur
        _ACCT_SNAP['ts'] = now
    rows = []
    total = 0
    for c in TRAFFIC_CLASSES:
        key = 'c_' + c['key']
        v = cur.get(key) or {'packets': 0, 'bytes': 0}
        total += v['bytes']
        rows.append({'key': c['key'], 'label': c['label'], 'color': c['color'],
                     'bytes': v['bytes'], 'packets': v['packets'],
                     'rate': rates.get(key, 0.0), 'pct': 0.0})
    for r in rows:
        r['pct'] = (r['bytes'] * 100.0 / total) if total else 0.0
    rows.sort(key=lambda r: r['bytes'], reverse=True)
    return rows, total


def deny_hits():
    """拒绝规则命中合计(packets/bytes)。"""
    ctr = get_nft_counters('filter')
    tot = {'packets': 0, 'bytes': 0}
    for k, v in ctr.items():
        if re.match(r'^d\d+$', k):
            tot['packets'] += v['packets']
            tot['bytes'] += v['bytes']
    return tot


def fmt_bytes(n, suffix=''):
    try:
        n = float(n)
    except Exception:
        n = 0.0
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return ('%.0f %s%s' % (n, u, suffix)) if u == 'B' else ('%.1f %s%s' % (n, u, suffix))
        n /= 1024.0


def fmt_dur(s):
    """秒 → 天/时:分:秒。"""
    try:
        s = int(s)
    except Exception:
        s = 0
    if s <= 0:
        return ''
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    core = '%02d:%02d:%02d' % (h, m, sec)
    return ('%d天 %s' % (d, core)) if d else core


def metrics_payload():
    ifs = if_stats()
    wan = ifs.get(WAN_IF) or {}
    lan = ifs.get(LAN_IF) or {}
    rows, total = acct_stats()
    dh = deny_hits()
    return {
        'ts': round(time.time(), 3),
        'wan': {'rx_rate': round(wan.get('rx_rate', 0.0), 1),
                'tx_rate': round(wan.get('tx_rate', 0.0), 1),
                'rx_bytes': wan.get('rx_bytes', 0), 'tx_bytes': wan.get('tx_bytes', 0)},
        'lan': {'rx_rate': round(lan.get('rx_rate', 0.0), 1),
                'tx_rate': round(lan.get('tx_rate', 0.0), 1),
                'rx_bytes': lan.get('rx_bytes', 0), 'tx_bytes': lan.get('tx_bytes', 0)},
        'cats': [{'key': r['key'], 'label': r['label'], 'color': r['color'],
                  'bytes': r['bytes'], 'rate': round(r['rate'], 1),
                  'pct': round(r['pct'], 2)} for r in rows],
        'total_bytes': total,
        'deny': dh,
    }


# ============ 会话 ============
def get_token_from_cookie(headers):
    c = headers.get('Cookie')
    if not c:
        return None
    for part in c.split(';'):
        part = part.strip()
        if part.startswith('sid='):
            return part[4:]
    return None

def valid_session(token):
    if not token or token not in sessions:
        return False
    if sessions[token]['exp'] < time.time():
        del sessions[token]
        return False
    return True

def new_session():
    token = secrets.token_hex(16)
    sessions[token] = {'exp': time.time() + SESSION_TTL}
    return token

# ============ HTML ============
PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,"Microsoft YaHei",sans-serif;margin:0;background:#f4f6f9;color:#222}}
header{{background:linear-gradient(90deg,#1b3557 0%,#24466f 100%);color:#fff;padding:11px 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;box-shadow:0 2px 10px rgba(15,35,60,.22)}}
header h1{{font-size:16.5px;margin:0;display:flex;align-items:center;gap:9px;letter-spacing:.3px;white-space:nowrap}}
header h1 svg{{width:21px;height:21px;flex:none;opacity:.95}}
.nav{{display:flex;gap:4px;flex-wrap:wrap;align-items:center}}
.nav a{{display:inline-flex;align-items:center;gap:6px;color:#cddff2;padding:7px 11px;border-radius:9px;text-decoration:none;font-size:13.5px;line-height:1;transition:background .15s ease,color .15s ease}}
.nav a svg{{width:15px;height:15px;flex:none;opacity:.95}}
.nav a:hover{{background:rgba(255,255,255,.13);color:#fff}}
.nav a.active{{background:#2e7dd1;color:#fff;box-shadow:0 2px 7px rgba(0,0,0,.28)}}
.nav a.logout{{color:#f0c6c3;margin-left:6px}}
.nav a.logout:hover{{background:rgba(217,83,79,.32);color:#fff}}
.container{{max-width:1080px;margin:20px auto;padding:0 16px}}
.card{{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);padding:18px 20px;margin-bottom:18px}}
.card h2{{font-size:16px;margin:0 0 12px;color:#1f3a5f;border-left:4px solid #2e7dd1;padding-left:10px}}
.card h3{{font-size:14px;margin:14px 0 8px;color:#335}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #eee}}
th{{color:#666;font-weight:600}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;color:#fff}}
.ok{{background:#2e9e5b}}.bad{{background:#d9534f}}.warn{{background:#e0a800}}.info{{background:#2e7dd1}}
.btn{{display:inline-block;padding:7px 14px;background:#2e7dd1;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px;text-decoration:none}}
.btn:hover{{background:#1f6bb5}}
.btn.sm{{padding:4px 10px;font-size:12px}}
.btn.danger{{background:#d9534f}}
form.inline{{display:inline}}
input,select{{padding:6px 8px;border:1px solid #ccc;border-radius:6px;font-size:13px}}
.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:8px}}
.msg{{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px}}
.msg{{position:sticky;top:0;z-index:30}}
.card{{scroll-margin-top:60px}}
.msg.info{{background:#e7f1fb;color:#1f6bb5}}.msg.err{{background:#fdecea;color:#c0392b}}
pre{{background:#0f1b2d;color:#d6e7ff;padding:12px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}}
a.link{{color:#2e7dd1;text-decoration:none}}
.tip{{color:#888;font-size:12px;margin-top:6px}}
.sub{{border:1px solid #eef; border-radius:8px; padding:12px 14px; margin-bottom:12px; background:#fafcff}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:4px}}
.metric{{background:linear-gradient(160deg,#f8fbfe,#edf4fc);border:1px solid #e2ecf8;border-radius:9px;padding:11px 14px}}
.mlabel{{font-size:12px;color:#6f839b;margin-bottom:5px}}
.mval{{font-size:19px;font-weight:600;color:#16304f;font-variant-numeric:tabular-nums}}
.msub{{font-size:11.5px;color:#8ea2b8;margin-top:3px;font-variant-numeric:tabular-nums}}
.bar{{height:7px;background:#eef1f5;border-radius:4px;overflow:hidden;min-width:80px}}
.bar span{{display:block;height:100%;border-radius:4px;transition:width .45s ease}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:1px}}
.num{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
.dim{{color:#a7b4c4}}
.tun{{font-variant-numeric:tabular-nums;line-height:1.45}}
.tun b{{font-weight:600;color:#16304f}}
.tun small{{display:block;color:#8ea2b8;font-size:11px}}
.spark{{width:100%;height:74px;background:#0f1b2d;border-radius:8px;display:block;margin-top:2px}}
.footer{{max-width:1080px;margin:4px auto 24px;padding:14px 16px 0;border-top:1px solid #e3eaf2;
  text-align:center;color:#93a6ba;font-size:12px;line-height:1.7}}
.footer .ver{{display:inline-block;margin-left:8px;padding:1px 8px;border-radius:9px;
  background:#eef3f9;color:#5b7a99}}
</style></head>
<body>
<header><h1>{logo}路由管理 · RouteWeb</h1>
{nav}
</header>
<div class="container">{body}</div>{js}
<footer class="footer">{copyright}</footer>
</body></html>"""
PAGE = PAGE.replace('{{', '{').replace('}}', '}')

# ---- 内联 SVG 图标(零依赖, 随 currentColor 变色) ----
ICON = {
    'router': '<rect x="2" y="14" width="20" height="7" rx="2"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/>'
              '<line x1="10.5" y1="17.5" x2="10.51" y2="17.5"/><path d="M12 14V9.5"/>'
              '<path d="M8.6 6.2a4.8 4.8 0 0 1 6.8 0"/><path d="M5.6 3.2a9 9 0 0 1 12.8 0"/>',
    'dash': '<rect x="3" y="3" width="7" height="7" rx="1.6"/><rect x="14" y="3" width="7" height="7" rx="1.6"/>'
            '<rect x="3" y="14" width="7" height="7" rx="1.6"/><rect x="14" y="14" width="7" height="7" rx="1.6"/>',
    'vpn': '<path d="M12 22s8-4.2 8-10V5.2L12 2 4 5.2V12c0 5.8 8 10 8 10z"/><path d="M9 11.6l2.1 2.1L15 9.8"/>',
    'client': '<path d="M15 3h3.5A2.5 2.5 0 0 1 21 5.5v13a2.5 2.5 0 0 1-2.5 2.5H15"/>'
              '<polyline points="10 16.5 14.5 12 10 7.5"/><line x1="14.5" y1="12" x2="3" y2="12"/>',
    'dhcp': '<rect x="2.5" y="3" width="19" height="7.5" rx="2"/><rect x="2.5" y="13.5" width="19" height="7.5" rx="2"/>'
            '<line x1="6.5" y1="6.75" x2="6.51" y2="6.75"/><line x1="6.5" y1="17.25" x2="6.51" y2="17.25"/>',
    'net': '<circle cx="18" cy="5" r="2.6"/><circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="19" r="2.6"/>'
           '<line x1="8.5" y1="13.4" x2="15.6" y2="17.7"/><line x1="15.6" y1="6.3" x2="8.5" y2="10.6"/>',
    'fw': '<rect x="3" y="5" width="18" height="14" rx="1.6"/><line x1="3" y1="12" x2="21" y2="12"/>'
          '<line x1="9" y1="5" x2="9" y2="12"/><line x1="15" y1="12" x2="15" y2="19"/>',
    'tools': '<path d="M3 12h3.4l2.1-6.2 3.3 12.4 2.3-6.2H21"/>',
    'logout': '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>'
              '<polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
}

NAV_ITEMS = [
    ('/', '仪表盘', 'dash'),
    ('/vpn', '虚拟专网', 'vpn'),
    ('/clients', '客户端', 'client'),
    ('/dhcp', 'DHCP', 'dhcp'),
    ('/network', '网络配置', 'net'),
    ('/firewall', '防火墙', 'fw'),
    ('/tools', '网络工具', 'tools'),
]


def ico(name, cls=''):
    """渲染一个内联 SVG 图标。"""
    inner = ICON.get(name, '')
    return ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" '
            'stroke-linecap="round" stroke-linejoin="round"%s aria-hidden="true">%s</svg>'
            % ((' class="%s"' % cls) if cls else '', inner))


def nav_html(path='/'):
    """顶部操作菜单: 图标 + 文字, 并按当前路径高亮。"""
    out = []
    for href, label, ic in NAV_ITEMS:
        cls = ' class="active"' if path == href else ''
        out.append('<a href="%s"%s title="%s">%s<span>%s</span></a>'
                   % (href, cls, label, ico(ic), label))
    out.append('<a href="/?logout=1" class="logout" title="退出登录">%s<span>退出</span></a>'
               % ico('logout'))
    return '<div class="nav">%s</div>' % ''.join(out)


STAY_JS = """
(function(){
var allow=['/','/vpn','/clients','/dhcp','/network','/firewall','/tools'];
function cur(){
  var p=location.pathname;
  if(allow.indexOf(p)<0){p='/';}
  return p;
}
function cardOf(f){
  var el=f;
  while(el&&el!==document.body){
    if(el.className&&String(el.className).indexOf('card')>=0&&el.id){return el;}
    el=el.parentNode;
  }
  return null;
}
try{
var forms=document.querySelectorAll('form[action="/action"]');
for(var i=0;i<forms.length;i++){
  var f=forms[i];
  if(f.querySelector('input[name="ret"]')){continue;}
  var c=cardOf(f);
  var inp=document.createElement('input');
  inp.type='hidden';
  inp.name='ret';
  inp.value=cur()+(c?'#'+c.id:'');
  f.appendChild(inp);
}
}catch(e){}
})();
"""


def copyright_html():
    """页面最下方的版权信息: 开发方 + 发布日期 + 版本号。"""
    return ('&copy; %s · %s · 版本号 <span class="ver">%s</span>'
            % (esc(APP_VENDOR), esc(APP_RELDATE), esc(APP_VERSION)))


def page(title, body, path='/', show_nav=True):
    nav = nav_html(path) if show_nav else ''
    return (PAGE.replace('{title}', title)
                .replace('{logo}', ico('router'))
                .replace('{nav}', nav)
                .replace('{js}', '<script>' + STAY_JS + '</script>')
                .replace('{copyright}', copyright_html())
                .replace('{body}', body))

def esc(s):
    return html.escape(str(s))

def card(title, inner):
    cid = 'card-' + hashlib.md5(str(title).encode('utf-8')).hexdigest()[:8]
    return '<div class="card" id="%s"><h2>%s</h2>%s</div>' % (cid, esc(title), inner)

def badge(state):
    if state in ('active', '运行中', '已安装', '已连接', '在线', True):
        return '<span class="badge ok">%s</span>' % esc(str(state))
    if state in ('未安装', '未连接', '离线', False):
        return '<span class="badge bad">%s</span>' % esc(str(state))
    return '<span class="badge warn">%s</span>' % esc(str(state))

# ---- 仪表盘 ----
# ---- 仪表盘 ----
TRAFFIC_JS = """
(function(){
var hist=[],MAX=60;
function fmt(n,s){s=s||'';n=Number(n)||0;var u=['B','KB','MB','GB','TB'],i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (i===0?n.toFixed(0):n.toFixed(1))+' '+u[i]+s;}
function render(d){
  var t='';
  (d.cats||[]).forEach(function(c){
    t+='<tr><td><span class="dot" style="background:'+c.color+'"></span>'+c.label+'</td>'+
       '<td><div class="bar"><span style="width:'+c.pct.toFixed(1)+'%;background:'+c.color+'"></span></div></td>'+
       '<td class="num">'+fmt(c.bytes)+'</td>'+
       '<td class="num">'+fmt(c.rate,'/s')+'</td></tr>';
  });
  var b=document.getElementById('catbody');
  if(b){b.innerHTML=t||'<tr><td colspan="4">暂无数据</td></tr>';}
}
function spark(){
  var el=document.getElementById('sparkline');if(!el){return;}
  var max=1;hist.forEach(function(v){if(v>max){max=v;}});
  var n=hist.length,pts=[],i,x,y;
  for(i=0;i<n;i++){
    x=(n===1)?340:i*680/(n-1);
    y=70-(hist[i]/max)*62;
    pts.push(x.toFixed(1)+','+y.toFixed(1));
  }
  el.setAttribute('points',pts.join(' '));
}
function setv(id,v){var e=document.getElementById(id);if(e){e.textContent=v;}}
function poll(){
  fetch('/metrics',{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
    setv('m-rx',fmt(d.wan.rx_rate,'/s'));
    setv('m-rx-sub','累计 '+fmt(d.wan.rx_bytes));
    setv('m-tx',fmt(d.wan.tx_rate,'/s'));
    setv('m-tx-sub','累计 '+fmt(d.wan.tx_bytes));
    setv('m-lan',fmt(d.lan.rx_rate+d.lan.tx_rate,'/s'));
    setv('m-lan-sub','下行 '+fmt(d.lan.rx_rate,'/s')+' · 上行 '+fmt(d.lan.tx_rate,'/s'));
    setv('m-deny',String(d.deny.packets));
    setv('m-deny-sub','累计 '+fmt(d.deny.bytes));
    render(d);
    hist.push((d.wan.rx_rate||0)+(d.wan.tx_rate||0));
    if(hist.length>MAX){hist.shift();}
    spark();
  }).catch(function(){});
}
poll();setInterval(poll,3000);
})();
"""


def _cat_rows(rows):
    out = []
    for r in rows:
        out.append('<tr><td><span class="dot" style="background:%s"></span>%s</td>'
                   '<td><div class="bar"><span style="width:%.1f%%;background:%s"></span></div></td>'
                   '<td class="num">%s</td><td class="num">%s</td></tr>'
                   % (r['color'], esc(r['label']), r['pct'], r['color'],
                      fmt_bytes(r['bytes']), fmt_bytes(r['rate'], '/s')))
    return ''.join(out) or '<tr><td colspan="4">暂无数据</td></tr>'


def build_traffic_card():
    ifs = if_stats()
    wan = ifs.get(WAN_IF) or {}
    lan = ifs.get(LAN_IF) or {}
    rows, total = acct_stats()
    dh = deny_hits()
    b = '<div class="card"><h2>网络流量监视</h2>'
    b += '<div class="metrics">'
    b += ('<div class="metric"><div class="mlabel">WAN 下行（接收）</div>'
          '<div class="mval" id="m-rx">%s</div><div class="msub" id="m-rx-sub">累计 %s</div></div>'
          % (fmt_bytes(wan.get('rx_rate', 0), '/s'), fmt_bytes(wan.get('rx_bytes', 0))))
    b += ('<div class="metric"><div class="mlabel">WAN 上行（发送）</div>'
          '<div class="mval" id="m-tx">%s</div><div class="msub" id="m-tx-sub">累计 %s</div></div>'
          % (fmt_bytes(wan.get('tx_rate', 0), '/s'), fmt_bytes(wan.get('tx_bytes', 0))))
    b += ('<div class="metric"><div class="mlabel">LAN 双向合计</div>'
          '<div class="mval" id="m-lan">%s</div><div class="msub" id="m-lan-sub">下行 %s · 上行 %s</div></div>'
          % (fmt_bytes(lan.get('rx_rate', 0) + lan.get('tx_rate', 0), '/s'),
             fmt_bytes(lan.get('rx_rate', 0), '/s'), fmt_bytes(lan.get('tx_rate', 0), '/s')))
    b += ('<div class="metric"><div class="mlabel">防火墙已拦截</div>'
          '<div class="mval" id="m-deny">%d</div><div class="msub" id="m-deny-sub">累计 %s</div></div>'
          % (dh['packets'], fmt_bytes(dh['bytes'])))
    b += '</div>'
    b += ('<h3>流量类型汇总 <span class="tip" style="font-weight:400">累计 %s（含被拦截流量）</span></h3>'
          % fmt_bytes(total))
    b += ('<table><thead><tr><th>流量类型</th><th>占比</th><th class="num">累计流量</th>'
          '<th class="num">当前速率</th></tr></thead><tbody id="catbody">')
    b += _cat_rows(rows)
    b += '</tbody></table>'
    b += ('<h3>总体速率趋势</h3>'
          '<svg class="spark" viewBox="0 0 680 74" preserveAspectRatio="none" aria-hidden="true">'
          '<polyline id="sparkline" fill="none" stroke="#4da3ff" stroke-width="1.6" '
          'stroke-linejoin="round" points=""/></svg>')
    b += ('<div class="tip">数据来源：nftables 按类型命名计数器 + /proc/net/dev 接口计数；'
          '每 3 秒自动刷新。修改防火墙规则不会清零统计，网关重启后从零开始。</div>')
    b += '<script>' + TRAFFIC_JS + '</script>'
    b += '</div>'
    return b


def build_web_access_card(state=None):
    """仪表盘: Web 管理登录地址 + VPN 隧道访问开关。"""
    state = state if state is not None else load_state()
    cfg = web_access_cfg(state)
    addrs = local_v4()
    rows = ''
    lan_ips = [a['addr'] for a in addrs if not is_tunnel_if(a['iface'])]
    if HOST in lan_ips or not lan_ips:
        lan_ips = [HOST] + [x for x in lan_ips if x != HOST]
    for ip in lan_ips:
        rows += ('<tr><td>内网 LAN</td><td>%s</td>'
                 '<td><a class="btn sm" href="http://%s:%d/" target="_blank">http://%s:%d/</a></td></tr>'
                 % (esc(LAN_IF), esc(ip), PORT, esc(ip), PORT))
    tun = [a for a in addrs if is_tunnel_if(a['iface'])]
    for a in tun:
        note = ('对端 %s' % esc(a['peer'])) if a.get('peer') else '隧道接口'
        rows += ('<tr><td>VPN %s</td><td>%s</td>'
                 '<td><a class="btn sm" href="http://%s:%d/" target="_blank">http://%s:%d/</a>'
                 '<small style="color:#8ea2b8"> %s</small></td></tr>'
                 % (esc(a['iface']), note, esc(a['addr']), PORT, esc(a['addr']), PORT, note))
    if not tun:
        rows += ('<tr><td>VPN 隧道</td><td colspan="2"><span class="dim">当前无活动隧道 —— '
                 '在“客户端”页连接 PPTP / L2TP / OpenVPN 后，此处会自动出现隧道登录地址</span></td></tr>')
    allow = ', '.join('%s(%s)' % (c, n) for c, n in web_allowed_sources(state))
    form = ('<form method="post" action="/action" class="row" style="margin-top:8px">'
            '<input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="web_access_save">'
            '<input type="hidden" name="ret" value="/">'
            '<label><input type="checkbox" name="vpn" value="on"%s> 允许通过 VPN 隧道地址登录</label> '
            '额外允许网段 <input name="extra" size="30" placeholder="192.168.10.0/24,10.0.0.0/8" value="%s">'
            '<button class="btn sm" type="submit">保存并应用</button></form>'
            % (' checked' if cfg['vpn'] else '', esc(cfg['extra'])))
    tip = ('<div class="tip">管理页面监听所有本机地址（含隧道），但只接受下列来源：%s。'
           '外网（WAN）默认不开放。若要从远端内网主机直接访问，请把该网段填入“额外允许网段”，'
           '或由对端把流量 NAT 到隧道地址。</div>' % esc(allow))
    return card('Web 管理登录地址',
                '<table><tr><th>类型</th><th>地址</th><th>登录链接</th></tr>%s</table>%s%s'
                % (rows, form, tip))


def build_dashboard(msg=''):
    b = ''
    if msg:
        b += '<div class="msg info">%s</div>' % esc(msg)
    b += build_traffic_card()
    b += card('网络接口', '<pre>%s</pre>' % esc(get_interfaces()))
    fwd = get_ip_forward()
    fstate = '已开启' if fwd == '1' else '已关闭'
    fbtn = '关闭' if fwd == '1' else '开启'
    fval = '0' if fwd == '1' else '1'
    b += card('IPv4 转发 (当前: %s)' % fstate,
              '<form class="inline" method="post" action="/action">'
              '<input type="hidden" name="csrf" value="{csrf}">'
              '<input type="hidden" name="action" value="forward">'
              '<input type="hidden" name="value" value="%s">'
              '<button class="btn sm" type="submit">%s转发</button></form>' % (fval, fbtn))
    b += card('路由表', '<pre>%s</pre>' % esc(get_routes()))
    svc = ''.join(
        '<tr><td>%s</td><td>%s</td><td><form class="inline" method="post" action="/action">'
        '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="restart">'
        '<input type="hidden" name="svc" value="%s"><button class="btn sm" type="submit">重启</button>'
        '</form></td></tr>' % (esc(n), badge(get_service_status(n) == 'active' and '运行中' or get_service_status(n)), n)
        for n in ['nftables', 'dnsmasq', 'routeweb'])
    b += card('服务状态', '<table><tr><th>服务</th><th>状态</th><th>操作</th></tr>%s</table>' % svc)
    b += card('NAT / 防火墙规则 (nftables)', '<pre>%s</pre>' % esc(get_nat_rules()))
    state = load_state()
    pf = state.get('port_forwards', [])
    rows = ''.join(
        '<tr><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td>'
        '<td><form class="inline" method="post" action="/action">'
        '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="del_pf">'
        '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button>'
        '</form></td></tr>' % (esc(p['proto']), esc(p['ext_port']), esc(p['int_ip']), esc(p['int_port']),
                               esc(p.get('desc', '')), i)
        for i, p in enumerate(pf))
    pf_form = ('<div class="row"><form method="post" action="/action" class="row">'
               '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="add_pf">'
               '<select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>'
               '外网端口 <input name="ext_port" size="6">'
               '内网IP <input name="int_ip" size="14">'
               '内网端口 <input name="int_port" size="6">'
               '备注 <input name="desc" size="12">'
               '<button class="btn sm" type="submit">添加端口转发</button></form></div>')
    b += card('端口转发 (DNAT)', '<table><tr><th>协议</th><th>外网端口</th><th>内网地址:端口</th><th>备注</th><th>操作</th></tr>%s</table>%s'
              % (rows or '<tr><td colspan="5">暂无端口转发</td></tr>', pf_form))
    ds = state.get('dhcp_static', [])
    drows = ''.join(
        '<tr><td>%s</td><td>%s</td><td>%s</td>'
        '<td><form class="inline" method="post" action="/action">'
        '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="del_dhcp">'
        '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button>'
        '</form></td></tr>' % (esc(d['mac']), esc(d['ip']), esc(d.get('desc', '')), i)
        for i, d in enumerate(ds))
    dform = ('<div class="row"><form method="post" action="/action" class="row">'
             '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="add_dhcp">'
             'MAC <input name="mac" size="18" placeholder="AA:BB:CC:DD:EE:FF">'
             '保留IP <input name="ip" size="14" placeholder="172.16.1.x">'
             '备注 <input name="desc" size="12">'
             '<button class="btn sm" type="submit">添加静态保留</button></form></div>')
    b += card('DHCP 静态保留', '<table><tr><th>MAC</th><th>IP</th><th>备注</th><th>操作</th></tr>%s</table>%s'
              % (drows or '<tr><td colspan="4">暂无静态保留</td></tr>', dform))
    leases = get_leases()
    lrows = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (esc(l['mac']), esc(l['ip']), esc(l['name'])) for l in leases)
    b += card('当前 DHCP 租约', '<table><tr><th>MAC</th><th>IP</th><th>主机名</th></tr>%s</table>'
              % (lrows or '<tr><td colspan="3">暂无租约</td></tr>'))
    b += build_web_access_card(state)
    b += card('修改 Web 登录密码',
              '<div class="row"><form method="post" action="/action" class="row">'
              '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="chpw">'
              '旧密码 <input type="password" name="oldpw" size="14">'
              '新密码 <input type="password" name="newpw" size="14">'
              '<button class="btn sm" type="submit">修改</button></form></div>'
              '<div class="tip">默认密码为 %s，首次使用请尽快修改。</div>' % esc(DEFAULT_PW))
    return b

# ---- 虚拟专网 ----
def build_vpn(msg=''):
    state = load_state()
    vpn = state['vpn']
    b = ''
    if msg:
        b += '<div class="msg info">%s</div>' % esc(msg)
    b += card('虚拟专网 (VPN)',
              '<div class="tip">本模块可安装并管理五种 VPN 服务。启用后系统会自动放行对应端口并对 VPN 客户端网段做 NAT 出网。'
              '客户端配置可在各协议卡片中复制。服务器公网地址：<b>%s</b></div>' % esc(wan_ip_live()))
    b += build_sessions_panel(state, None, '在线客户端（全部协议）')
    b += build_sessions_history()
    for proto in ['wireguard', 'openvpn', 'ikev2', 'l2tp', 'pptp']:
        inst = vpn_installed(proto)
        en = vpn[proto].get('enabled')
        act = vpn_active(proto)
        v = vpn[proto]
        inner = '<div class="row">'
        inner += badge(inst and '已安装' or '未安装') + ' '
        inner += badge(act and '运行中' or '未运行') + ' '
        inner += badge(en and '已启用' or '未启用')
        inner += '</div>'
        # 启用/停用 / 安装
        if not inst:
            inner += ('<form class="inline" method="post" action="/action">'
                      '<input type="hidden" name="csrf" value="{csrf}">'
                      '<input type="hidden" name="action" value="vpn_install">'
                      '<input type="hidden" name="proto" value="%s">'
                      '<button class="btn sm" type="submit">安装 %s</button></form>' % (proto, esc(VPN_LABEL[proto])))
        else:
            toggle = ('<form class="inline" method="post" action="/action">'
                      '<input type="hidden" name="csrf" value="{csrf}">'
                      '<input type="hidden" name="action" value="vpn_toggle">'
                      '<input type="hidden" name="proto" value="%s">'
                      '<input type="hidden" name="enable" value="%s">'
                      '<button class="btn sm %s" type="submit">%s</button></form>'
                      % (proto, '0' if en else '1', '' if en else '', '停用' if en else '启用'))
            inner += toggle
        # 各协议专属管理
        if inst and en:
            inner += _vpn_manage(proto, v)
        b += '<div class="sub"><h3>%s</h3>%s</div>' % (esc(VPN_LABEL[proto]), inner)
    return b

# ============ VPN 在线会话(服务端视角): 采集 / 管理 / 历史 ============
SESS_DIR = '/run/routeweb/sess'
SESS_LOG = '/var/log/routeweb-sessions.log'
OVPN_STATUS = '/var/log/openvpn-status.log'
OVPN_MGMT_HOST = '127.0.0.1'
OVPN_MGMT_PORT = 7505
OVPN_CCD = '/etc/openvpn/ccd'
OVPN_SERVER_CONF = '/etc/openvpn/server.conf'
WG_IF = 'wg0'
_SESS_CACHE = {}
_SESS_SEEN = {}


def human_bytes(n):
    try:
        n = float(n)
    except Exception:
        return '-'
    i = 0
    u = ['B', 'KB', 'MB', 'GB', 'TB']
    while n >= 1024 and i < 4:
        n /= 1024.0
        i += 1
    return ('%d %s' % (round(n), u[i])) if i == 0 else ('%.1f %s' % (n, u[i]))


def human_dur(s):
    try:
        s = int(s)
    except Exception:
        return '-'
    if s < 0:
        s = 0
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, sec = divmod(s, 60)
    core = '%02d:%02d:%02d' % (h, m, sec)
    return ('%d天' % d) + core if d else core


def iface_bytes(iface):
    """读网卡累计收发字节(接口已消失时返回 0)。"""
    rx = tx = 0
    if not re.match(r'^[A-Za-z0-9_.:-]{1,15}$', iface or ''):
        return 0, 0
    try:
        rx = int(open('/sys/class/net/%s/statistics/rx_bytes' % iface).read().strip())
        tx = int(open('/sys/class/net/%s/statistics/tx_bytes' % iface).read().strip())
    except Exception:
        pass
    return rx, tx


def _read_kv(path):
    d = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                d[k.strip()] = v.strip()
    except Exception:
        pass
    return d


def pppd_procs():
    """扫描 /proc 返回 {pid: {'ppid','pcomm','args'}}, 仅含 pppd 进程。

    pptpd / xl2tpd 是服务端 pppd 的父进程, 据此判定链路归属与协议;
    网关主动拨出的链路由命令行含 `call <名称>` 判定。
    """
    res = {}
    try:
        entries = [e for e in os.listdir('/proc') if e.isdigit()]
    except Exception:
        return res
    for e in entries:
        try:
            comm = open('/proc/%s/comm' % e).read().strip()
        except Exception:
            continue
        if comm != 'pppd':
            continue
        try:
            args = open('/proc/%s/cmdline' % e, 'rb').read().replace(b'\0', b' ').decode('utf-8', 'replace').strip()
        except Exception:
            args = ''
        ppid = 0
        try:
            ppid = int(open('/proc/%s/stat' % e).read().rsplit(')', 1)[1].split()[1])
        except Exception:
            pass
        pcomm = ''
        if ppid:
            try:
                pcomm = open('/proc/%d/comm' % ppid).read().strip()
            except Exception:
                pass
        res[int(e)] = {'ppid': ppid, 'pcomm': pcomm, 'args': args}
    return res


def _log_peer_ip(daemon, ppid):
    """从 pptpd / xl2tpd 日志回溯该连接的客户端公网 IP(结果缓存 60s)。"""
    if not ppid:
        return ''
    key = 'src-%s-%d' % (daemon, ppid)
    now = time.time()
    c = _SESS_CACHE.get(key)
    if c and now - c[0] < 60:
        return c[1]
    txt = ''
    rc, out, err = run(['journalctl', '-u', daemon, '--no-pager', '-n', '400'])
    txt += out or ''
    try:
        with open('/var/log/syslog', 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 60000), 0)
            txt += '\n' + f.read().decode('utf-8', 'replace')
    except Exception:
        pass
    ms = re.findall(r'%s\[%d\][^\n]*?(\d+\.\d+\.\d+\.\d+)' % (daemon, ppid), txt)
    ip = ms[-1] if ms else ''
    _SESS_CACHE[key] = (now, ip)
    return ip


SRV_DAEMONS = ('pptpd', 'pptpctrl', 'xl2tpd')


def _log_peer_user(pid):
    """从 pppd 日志回溯该链路的认证用户名(结果缓存 60s)。"""
    if not pid:
        return ''
    key = 'usr-%d' % pid
    now = time.time()
    c = _SESS_CACHE.get(key)
    if c and now - c[0] < 60:
        return c[1]
    txt = ''
    rc, out, err = run(['journalctl', '-u', 'pptpd', '-u', 'xl2tpd', '--no-pager', '-n', '400'])
    txt += out or ''
    try:
        with open('/var/log/syslog', 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 60000), 0)
            txt += '\n' + f.read().decode('utf-8', 'replace')
    except Exception:
        pass
    user = ''
    for pat in (r'pppd\[%d\][^\n]*?authentication succeeded for (\S+)' % pid,
                r'pppd\[%d\][^\n]*?peer (?:from )?(\S+) authenticated' % pid,
                r'[^\n]*?authentication succeeded for (\S+)'):
        ms = re.findall(pat, txt)
        if ms:
            user = ms[-1]
            break
    _SESS_CACHE[key] = (now, user)
    return user


def ppp_sessions():
    """PPTP / L2TP 服务端当前接入的客户端(PPP 链路)。

    判定依据: 钩子记录的 daemon(pppd 父进程名)。
      pptpd -> pptpctrl -> pppd / xl2tpd -> pppd  = 服务端接入的客户端
      其它(网关用 `pppd call <名称>` 主动拨出)     = 不属于本模块
    """
    out = []
    procs = pppd_procs()
    try:
        files = os.listdir(SESS_DIR)
    except Exception:
        files = []
    srv_procs = dict((p, i) for p, i in procs.items() if i.get('pcomm') in SRV_DAEMONS)
    for fn in files:
        if not fn.startswith('ppp-'):
            continue
        d = _read_kv(os.path.join(SESS_DIR, fn))
        try:
            pid = int(d.get('pid') or 0)
        except Exception:
            pid = 0
        info = procs.get(pid)
        if 'daemon' in d:
            # 新钩子: daemon 明确(空/非服务端 = 网关主动拨出的链路)
            if d.get('daemon') not in SRV_DAEMONS:
                continue
            daemon = d['daemon']
        else:
            # 老版本钩子没记 daemon: 用 pppd 的父进程兜底
            if info and info.get('pcomm') in SRV_DAEMONS:
                daemon = info['pcomm']
            elif not d.get('ipparam') and len(srv_procs) == 1:
                pid, info = list(srv_procs.items())[0]
                daemon = info['pcomm']
            else:
                continue
        role = 'l2tp' if daemon == 'xl2tpd' else 'pptp'
        iface = d.get('iface', '')
        try:
            since = int(d.get('since') or 0)
        except Exception:
            since = 0
        if not since and pid:
            try:
                since = int(os.stat('/proc/%d' % pid).st_mtime)
            except Exception:
                since = 0
        rx, tx = iface_bytes(iface)
        # 来源 IP: pptpd 把 ipparam 设为客户端公网 IP, 取不到再查日志
        src = d.get('ipparam', '') or ''
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', src):
            src = ''
        if not src and info:
            src = _log_peer_ip('pptpd' if role == 'pptp' else 'xl2tpd', info.get('ppid', 0))
        # PEERNAME 是认证用户名; PPPLOGNAME 是启动 pppd 的系统账号(root/mason), 不能用
        user = d.get('user', '') or ''
        if not user:
            user = _log_peer_user(pid)
        out.append({'proto': role, 'user': user or '-', 'src': src or '-',
                    'vip': d.get('remote', '') or '-', 'dev': iface, 'since': since,
                    'rx': rx, 'tx': tx, 'pid': pid, 'id': str(pid),
                    'local': d.get('local', '')})
    return out


def _ovpn_ts(s):
    """把 status 文件里的时间字符串转成时间戳(数字串直接用)。"""
    s = (s or '').strip()
    if not s:
        return 0
    if s.isdigit():
        try:
            return int(s)
        except Exception:
            return 0
    for fmt in ('%Y-%m-%d %H:%M:%S', '%a %b %d %H:%M:%S %Y', '%Y-%m-%d %H:%M'):
        try:
            return int(time.mktime(time.strptime(s, fmt)))
        except Exception:
            continue
    return 0


def ovpn_sessions():
    """解析 OpenVPN status 文件。

    同时兼容 status-version 1(旧格式: 客户端段无表头列名, 虚拟地址在 ROUTING TABLE)
    与 status-version 2(带 HEADER 列名的 CSV)。version 2 时按列名取值,
    避免不同版本列偏移不同导致的错位。
    """
    out = []
    try:
        txt = open(OVPN_STATUS).read()
    except Exception:
        return out
    dev = 'tun0'
    try:
        if os.path.exists(OVPN_SERVER_CONF):
            m = re.search(r'^dev\s+(\S+)', open(OVPN_SERVER_CONF).read(), re.M)
            if m:
                dev = m.group(1)
    except Exception:
        pass
    lines = txt.splitlines()
    hdr = []          # version 2: HEADER,CLIENT_LIST,<列名...>
    v1hdr = []        # version 1: 客户端段表头
    vip_of = {}       # CN -> 虚拟地址(version 1 只有 ROUTING TABLE 里有)
    for line in lines:
        if line.startswith('HEADER,CLIENT_LIST,'):
            hdr = [x.strip() for x in line.split(',')[2:]]
        elif line.startswith('Common Name,Real Address'):
            v1hdr = [x.strip() for x in line.split(',')]
    section = ''
    for line in lines:
        s = line.strip()
        if s.startswith('ROUTING TABLE'):
            section = 'rt'
            continue
        if s.startswith('GLOBAL STATS') or s.startswith('END') or s.startswith('OpenVPN CLIENT LIST'):
            section = 'cl'
            continue
        if section == 'rt' and s and not s.startswith('Virtual Address'):
            f = s.split(',')
            if len(f) >= 2:
                vip_of[f[1]] = f[0]
    idx = dict((h.lower().replace(' ', ''), i) for i, h in enumerate(hdr))

    def col(f, *names):
        for n in names:
            k = n.lower().replace(' ', '')
            if k in idx and idx[k] < len(f):
                return f[idx[k]]
        return ''

    def toint(v):
        try:
            return int(str(v).strip())
        except Exception:
            return 0

    sec = ''
    for s in lines:
        s = s.strip()
        # 只解析"客户端列表"段, ROUTING TABLE / GLOBAL STATS 的行不能当客户端
        if s.startswith('OpenVPN CLIENT LIST') or s.startswith('TITLE'):
            sec = 'cl'
            continue
        if s.startswith('ROUTING TABLE'):
            sec = 'rt'
            continue
        if s.startswith('GLOBAL STATS') or s.startswith('END'):
            sec = ''
            continue
        if sec != 'cl':
            continue
        if s.startswith('CLIENT_LIST,'):
            f = s.split(',')[1:]
            cn = col(f, 'Common Name') or (f[0] if f else '')
            real = col(f, 'Real Address')
            vip = col(f, 'Virtual Address') or vip_of.get(cn, '')
            rx = toint(col(f, 'Bytes Received'))
            tx = toint(col(f, 'Bytes Sent'))
            since = _ovpn_ts(col(f, 'Connected Since (time_t)', 'Connected Since(time_t)',
                                 'Connected Since'))
            out.append({'proto': 'openvpn', 'user': cn, 'src': (real.split(':')[0] or '-'),
                        'vip': vip or '-', 'dev': dev, 'since': since, 'rx': rx, 'tx': tx,
                        'pid': 0, 'id': cn})
        elif v1hdr and s and ',' in s and not s.startswith(('Updated', 'TITLE', 'TIME',
                                                            'HEADER', 'GLOBAL', 'END',
                                                            'Common Name', 'Virtual Address',
                                                            'ROUTING', 'OpenVPN')):
            # version 1: 客户端段是裸 CSV 行, 无 CLIENT_LIST 前缀
            f = s.split(',')
            m = dict((h, (f[i] if i < len(f) else '')) for i, h in enumerate(v1hdr))
            cn = m.get('Common Name', '')
            if not cn or 'Bytes Received' not in m:
                continue
            real = m.get('Real Address', '')
            out.append({'proto': 'openvpn', 'user': cn, 'src': (real.split(':')[0] or '-'),
                        'vip': vip_of.get(cn, '-'), 'dev': dev,
                        'since': _ovpn_ts(m.get('Connected Since', '')),
                        'rx': toint(m.get('Bytes Received')), 'tx': toint(m.get('Bytes Sent')),
                        'pid': 0, 'id': cn})
    return out


def wg_sessions(state=None):
    """WireGuard 对等体在线情况(以最近握手时间判断)。"""
    out = []
    st = state or load_state()
    peers = st.get('vpn', {}).get('wireguard', {}).get('peers', [])
    name_of = dict((p.get('pub', ''), p.get('name', '')) for p in peers if p.get('pub'))
    rc, o, e = run(['wg', 'show', WG_IF, 'dump'])
    if rc != 0:
        return out
    for ln in o.strip().splitlines()[1:]:
        f = ln.split('\t')
        if len(f) < 7:
            continue
        pub, endpoint, allowed, hs, rx, tx = f[0], f[2], f[3], f[4], f[5], f[6]
        try:
            hs = int(hs)
        except Exception:
            hs = 0
        try:
            rx, tx = int(rx), int(tx)
        except Exception:
            rx = tx = 0
        since = int(time.time()) - hs if hs > 0 else 0
        out.append({'proto': 'wireguard', 'user': name_of.get(pub) or (pub[:10] + '…'),
                    'src': endpoint.split(':')[0] if endpoint and endpoint != '(none)' else '-',
                    'vip': (allowed.split(',')[0] if allowed else '-'), 'dev': WG_IF,
                    'since': since, 'rx': rx, 'tx': tx, 'pid': 0, 'id': pub,
                    'handshake': hs, 'live': (0 < hs < 180)})
    return out


def ike_sessions():
    """strongSwan 当前 IKEv2 安全关联。"""
    out = []
    rc, o, e = run(['swanctl', '--list-sas'])
    if rc != 0 or not o.strip():
        return out
    cur = None
    for line in o.splitlines():
        s = line.strip()
        m = re.match(r'^(\S+):\s+#(\d+),\s+(\w+),\s+IKEv', s)
        if m:
            cur = {'proto': 'ikev2', 'user': '-', 'src': '-', 'vip': '-', 'dev': '-',
                   'since': 0, 'rx': 0, 'tx': 0, 'pid': 0, 'id': m.group(2),
                   'state': m.group(3)}
            out.append(cur)
            continue
        if cur is None:
            continue
        m2 = re.match(r"^remote\s+'?([^']*)'?\s+@\s+(\d+\.\d+\.\d+\.\d+)", s)
        if m2:
            cur['user'] = m2.group(1) or '-'
            cur['src'] = m2.group(2)
            continue
        m3 = re.match(r'^remote\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?', s)
        if m3 and cur['vip'] == '-':
            cur['vip'] = m3.group(1)
            continue
        m4 = re.match(r'^installed\s+(\d+)s\s+ago', s)
        if m4:
            try:
                cur['since'] = int(time.time()) - int(m4.group(1))
            except Exception:
                pass
            continue
        m5 = re.match(r'^in\s+\S+,\s+(\d+)\s+bytes', s)
        if m5:
            try:
                cur['rx'] = int(m5.group(1))
            except Exception:
                pass
            continue
        m6 = re.match(r'^out\s+\S+,\s+(\d+)\s+bytes', s)
        if m6:
            try:
                cur['tx'] = int(m6.group(1))
            except Exception:
                pass
    return [x for x in out if x.get('state') == 'ESTABLISHED']


def sess_key(x):
    return '%s|%s|%s' % (x.get('proto'), x.get('id'), x.get('vip'))


def log_session(x, end_ts):
    """把一条已结束的会话追加到历史日志(TSV)。"""
    try:
        since = int(x.get('since') or 0)
        dur = max(0, end_ts - since) if since else 0
        line = '\t'.join([str(end_ts), x.get('proto', ''), x.get('user', ''),
                          x.get('src', ''), x.get('vip', ''), str(since), str(dur),
                          str(x.get('rx', 0)), str(x.get('tx', 0))])
        with open(SESS_LOG, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


def sess_rotate(cur):
    """与上一次快照比对, 把已消失的会话记入历史(供"连接历史"展示)。"""
    now = dict((sess_key(x), x) for x in cur)
    prev = _SESS_SEEN.get('snap') or {}
    if _SESS_SEEN.get('init'):
        end = int(time.time())
        for k, x in prev.items():
            # PPP 由 ip-down 钩子记录(能读到断开前的流量), 这里只兜底其他协议
            if k not in now and x.get('proto') not in ('pptp', 'l2tp'):
                log_session(x, end)
    _SESS_SEEN['snap'] = now
    _SESS_SEEN['init'] = True


def vpn_sessions(state=None, proto=None):
    """汇总所有协议的在线客户端。"""
    st = state or load_state()
    all_s = []
    all_s += ppp_sessions()
    all_s += ovpn_sessions()
    all_s += wg_sessions(st)
    all_s += ike_sessions()
    sess_rotate(all_s)
    if proto:
        all_s = [x for x in all_s if x.get('proto') == proto]
    all_s.sort(key=lambda x: (x.get('proto', ''), -(x.get('since') or 0)))
    return all_s


def sess_history(limit=100):
    rows = []
    try:
        with open(SESS_LOG) as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception:
        return rows
    for l in lines[-limit:]:
        f = l.split('\t')
        if len(f) < 9:
            continue
        rows.append({'end': int(f[0]) if f[0].isdigit() else 0, 'proto': f[1],
                     'user': f[2], 'src': f[3], 'vip': f[4],
                     'since': int(f[5]) if f[5].isdigit() else 0,
                     'dur': int(f[6]) if f[6].isdigit() else 0,
                     'rx': int(f[7]) if f[7].isdigit() else 0,
                     'tx': int(f[8]) if f[8].isdigit() else 0})
    rows.reverse()
    return rows


def sess_history_clear():
    try:
        with open(SESS_LOG, 'w'):
            pass
        return True
    except Exception:
        return False


def ovpn_mgmt(cmd, timeout=4.0):
    """通过 OpenVPN management 接口执行命令(仅本地回环)。"""
    try:
        s = socket.create_connection((OVPN_MGMT_HOST, OVPN_MGMT_PORT), timeout=timeout)
    except Exception as e:
        return False, '无法连接管理接口(%s)' % type(e).__name__
    buf = b''
    try:
        s.settimeout(timeout)
        try:
            s.recv(65536)
        except Exception:
            pass
        s.sendall((cmd + '\n').encode('utf-8'))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            if b'SUCCESS' in buf or b'ERROR' in buf:
                break
    finally:
        try:
            s.close()
        except Exception:
            pass
    txt = buf.decode('utf-8', 'replace')
    return ('SUCCESS' in txt), txt.strip().replace('\r', '')[:200]


def sess_kick(proto, sid):
    """断开指定在线会话。返回 (ok, msg)。"""
    sid = (sid or '').strip()
    if proto in ('pptp', 'l2tp'):
        if not sid.isdigit():
            return False, '参数错误'
        pid = int(sid)
        try:
            comm = open('/proc/%d/comm' % pid).read().strip()
        except Exception:
            return False, '会话已不存在'
        if comm != 'pppd':
            return False, '目标进程不是 pppd, 已拒绝操作'
        run(['kill', '-TERM', str(pid)])
        time.sleep(1.2)
        if os.path.exists('/proc/%d' % pid):
            run(['kill', '-KILL', str(pid)])
        return True, '已断开该连接'
    if proto == 'openvpn':
        if not re.match(r'^[A-Za-z0-9_.-]{1,64}$', sid):
            return False, '参数错误'
        ok, msg = ovpn_mgmt('kill %s' % sid)
        return (True, '已断开该连接') if ok else (False, '断开失败: ' + (msg or '未知'))
    if proto == 'wireguard':
        if not re.match(r'^[A-Za-z0-9+/=]{20,64}$', sid):
            return False, '参数错误'
        rc, out, err = run(['wg', 'set', WG_IF, 'peer', sid, 'remove'])
        return (rc == 0, '已断开该对等体' if rc == 0 else ('断开失败: ' + (err or out).strip()[:120]))
    if proto == 'ikev2':
        if not sid.isdigit():
            return False, '参数错误'
        rc, out, err = run(['swanctl', '--terminate', '--ike-id', sid])
        return (rc == 0, '已终止该连接' if rc == 0 else ('断开失败: ' + (err or out).strip()[:120]))
    return False, '不支持的协议'


def ovpn_server_net(v=None):
    """OpenVPN 服务端客户端网段: 返回 (network_str, netmask_str)。"""
    if v is None:
        try:
            v = load_state()['vpn'].get('openvpn', {})
        except Exception:
            v = {}
    local = (v.get('local') or '') if isinstance(v, dict) else ''
    if not is_cidr(local):
        local = VPN_DEF_LOCAL.get('openvpn', '10.8.0.0/24')
    try:
        import ipaddress as _ipa
        n = _ipa.ip_network(local, strict=False)
        return str(n.network_address), str(n.netmask)
    except Exception:
        return '10.8.0.0', '255.255.255.0'


def ovpn_static_ip_check(ip, name=None, state=None):
    """校验 OpenVPN 客户端固定隧道 IP。

    返回 (ok, msg): ok=False 表示不可用; ok=True 且 msg 非空表示可用但有提示(如落在动态池内)。
    """
    ip = (ip or '').strip()
    if not ip:
        return True, ''
    if not is_ip(ip):
        return False, 'IP 地址格式不正确'
    if state is None:
        state = load_state()
    v = state.get('vpn', {}).get('openvpn', {})
    try:
        import ipaddress as _ipa
        net = _ipa.ip_network(v.get('local') or VPN_DEF_LOCAL.get('openvpn', '10.8.0.0/24'), strict=False)
        addr = _ipa.ip_address(ip)
    except Exception:
        return False, 'IP 地址格式不正确'
    if addr not in net:
        return False, 'IP 不在客户端网段 %s 内' % str(net)
    if addr == net.network_address or addr == net.broadcast_address:
        return False, '不能使用网段的网络地址或广播地址'
    srv = vpn_server_addr('openvpn', v)
    if srv and ip == srv:
        return False, '该地址是服务端隧道地址 %s' % srv
    for c in v.get('clients', []):
        if c.get('name') == name:
            continue
        if (c.get('ip') or '').strip() == ip:
            return False, '该地址已分配给客户端 %s' % c.get('name')
    _ps, _pe = vpn_pool_range('openvpn', v)
    if _ps and _pe:
        try:
            if int(_ipa.ip_address(_ps)) <= int(addr) <= int(_ipa.ip_address(_pe)):
                return True, '提示: 该地址落在动态池 %s-%s 内, 若与该客户端同时在线的其它客户端先占用会冲突, 建议改用池外地址' % (_ps, _pe)
        except Exception:
            pass
    return True, ''


def ovpn_ccd_path(name):
    return os.path.join(OVPN_CCD, dl_safe_name(name))


def ovpn_ccd_content(name, c, state=None):
    """生成某个客户端的 client-config-dir 文件内容(disable + 固定 IP)。"""
    lines = []
    if c.get('disabled'):
        lines.append('disable')
    ip = (c.get('ip') or '').strip()
    if ip:
        ok, _m = ovpn_static_ip_check(ip, c.get('name'), state)
        if ok:
            _net, _mask = ovpn_server_net(state.get('vpn', {}).get('openvpn', {}) if state else None)
            lines.append('ifconfig-push %s %s' % (ip, _mask))
    return '\n'.join(lines) + ('\n' if lines else '')


def ovpn_write_ccd(name, c=None, state=None):
    """写入(或清理)某个客户端的 CCD 文件。返回 True/False。"""
    if state is None:
        state = load_state()
    if c is None:
        c = {}
        for x in state.get('vpn', {}).get('openvpn', {}).get('clients', []):
            if x.get('name') == name:
                c = x
                break
    try:
        os.makedirs(OVPN_CCD, exist_ok=True)
        os.chmod(OVPN_CCD, 0o755)
    except Exception:
        pass
    txt = ovpn_ccd_content(name, c, state)
    p = ovpn_ccd_path(name)
    try:
        if txt.strip():
            with open(p, 'w') as f:
                f.write(txt)
        elif os.path.exists(p):
            os.remove(p)
        return True
    except Exception:
        return False


def ovpn_sync_ccd(state=None):
    """把所有 OpenVPN 客户端的 CCD 文件按 state 重写一遍。返回写入个数。"""
    if state is None:
        state = load_state()
    n = 0
    for c in state.get('vpn', {}).get('openvpn', {}).get('clients', []):
        if ovpn_write_ccd(c.get('name', ''), c, state):
            n += 1
    return n


def ovpn_set_disabled(name, disabled):
    """OpenVPN: 用 client-config-dir 的 disable 指令阻断指定 CN(保留固定 IP 配置)。"""
    st = load_state()
    c = {}
    for x in st.get('vpn', {}).get('openvpn', {}).get('clients', []):
        if x.get('name') == name:
            c = x
            break
    c = dict(c)
    c['name'] = name
    c['disabled'] = bool(disabled)
    return ovpn_write_ccd(name, c, st)


def wg_sync_peers(state):
    """把 state 中未禁用的 peer 同步到运行中的 wg0(禁用=从运行时移除)。"""
    v = state.get('vpn', {}).get('wireguard', {})
    rc, out, err = run(['wg', 'show', WG_IF, 'dump'])
    if rc != 0:
        return 0
    live = []
    for ln in out.strip().splitlines()[1:]:
        f = ln.split('\t')
        if f:
            live.append(f[0])
    want = dict((p['pub'], p.get('allowed', '')) for p in v.get('peers', [])
                if p.get('pub') and not p.get('disabled'))
    n = 0
    for pub in live:
        if pub not in want:
            run(['wg', 'set', WG_IF, 'peer', pub, 'remove'])
            n += 1
    for pub, aip in want.items():
        if pub not in live and aip:
            run(['wg', 'set', WG_IF, 'peer', pub, 'allowed-ips', aip])
            n += 1
    return n


def sess_time_str(ts):
    try:
        ts = int(ts)
    except Exception:
        return '-'
    if not ts:
        return '-'
    t = time.localtime(ts)
    if time.strftime('%Y-%m-%d') != time.strftime('%Y-%m-%d', t):
        return time.strftime('%m-%d %H:%M', t)
    return time.strftime('%H:%M:%S', t)


def sess_rows_html(rows, show_proto=True):
    """渲染在线会话表格行(供页面与 /vpnsessions 共用)。"""
    if not rows:
        span = 9 if show_proto else 8
        return '<tr><td colspan="%d" class="dim">当前没有客户端连接</td></tr>' % span
    out = []
    for x in rows:
        proto = x.get('proto', '')
        kick = ('<form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}">'
                '<input type="hidden" name="action" value="vpn_kick">'
                '<input type="hidden" name="proto" value="%s">'
                '<input type="hidden" name="sid" value="%s">'
                '<button class="btn sm danger" type="submit" onclick="return confirm(\'确定断开该连接?\')">断开</button>'
                '</form>' % (esc(proto), esc(x.get('id', ''))))
        extra = ''
        if proto == 'wireguard' and x.get('handshake'):
            extra = '<small class="dim">握手 %ss 前</small>' % x['handshake']
        cells = []
        if show_proto:
            cells.append('<td>%s</td>' % esc(VPN_LABEL.get(proto, proto)))
        cells.append('<td><b>%s</b>%s</td>' % (esc(x.get('user', '-')),
                                               ('<small>%s</small>' % esc(x.get('dev', ''))) if x.get('dev') else ''))
        cells.append('<td>%s</td>' % esc(x.get('src', '-')))
        cells.append('<td>%s</td>' % esc(x.get('vip', '-')))
        cells.append('<td>%s</td>' % esc(sess_time_str(x.get('since'))))
        cells.append('<td data-since="%d">%s</td>' % (int(x.get('since') or 0),
                                                      esc(human_dur(int(time.time()) - int(x.get('since') or 0)) if x.get('since') else '-')))
        cells.append('<td>%s</td>' % esc(human_bytes(x.get('rx', 0))))
        cells.append('<td>%s</td>' % esc(human_bytes(x.get('tx', 0))))
        cells.append('<td>%s</td>' % kick)
        out.append('<tr>%s</tr>' % ''.join(cells))
    return ''.join(out)


SESS_JS = """
(function(){
  var p=%s, t=%s;
  function load(){
    var x=new XMLHttpRequest();
    x.open('GET','/vpnsessions'+(p?('?proto='+p):''),true);
    x.onload=function(){
      if(x.status!==200) return;
      var d; try{ d=JSON.parse(x.responseText); }catch(e){ return; }
      var b=document.getElementById('sess-body'+t); if(b) b.innerHTML=d.rows||'';
      var c=document.getElementById('sess-count'+t); if(c) c.textContent=d.n||0;
      var s=document.getElementById('sess-time'+t); if(s) s.textContent=d.time||'';
    };
    x.send();
  }
  if(document.getElementById('sess-body'+t)) setInterval(load,5000);
})();
"""


def sessions_table(state=None, proto=None, tag=''):
    """在线会话表格 + 5s 自动刷新脚本。tag 用于同页多表时区分元素 ID。"""
    st = state or load_state()
    rows = vpn_sessions(st, proto)
    head = ['协议', '账号 / 名称', '来源 IP', '隧道 IP', '上线时间', '时长', '↓ 接收', '↑ 发送', '操作']
    if proto:
        head = head[1:]
    th = ''.join('<th>%s</th>' % h for h in head)
    kick_all = ''
    if proto and rows:
        kick_all = ('<form class="inline" method="post" action="/action" '
                    'onsubmit="return confirm(\'确定断开该协议的全部连接?\')">'
                    '<input type="hidden" name="csrf" value="{csrf}">'
                    '<input type="hidden" name="action" value="vpn_kick_all">'
                    '<input type="hidden" name="proto" value="%s">'
                    '<button class="btn sm danger" type="submit">全部断开</button></form>' % esc(proto))
    body = ('<div class="row"><span class="tip">共 <b id="sess-count%s">%d</b> 个连接'
            '<span class="dim" id="sess-time%s"></span></span> %s</div>'
            '<table><tr>%s</tr><tbody id="sess-body%s">%s</tbody></table>'
            % (tag, len(rows), tag, kick_all, th, tag, sess_rows_html(rows, show_proto=(not proto))))
    body += '<script>%s</script>' % (SESS_JS % (
        "'%s'" % proto if proto else "''", "'%s'" % tag if tag else "''"))
    return body


def build_sessions_panel(state=None, proto=None, title='在线客户端', tag=''):
    st = state or load_state()
    return card(title, sessions_table(st, proto, tag))


def build_sessions_history(limit=50):
    """客户端连接历史(按断开时间倒序), 默认折叠。"""
    rows = sess_history(limit)
    if not rows:
        inner = ('<div class="tip">暂无记录。客户端断开后自动登记：协议、账号、来源 IP、隧道 IP、'
                 '上线时间、在线时长、收发流量。</div>')
    else:
        tr = ''
        for r in rows:
            tr += ('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                   '<td>%s</td><td>%s</td></tr>'
                   % (esc(sess_time_str(r['end'])), esc(VPN_LABEL.get(r['proto'], r['proto'])),
                      esc(r['user'] or '-'), esc(r['src'] or '-'), esc(r['vip'] or '-'),
                      esc(human_dur(r['dur'])), esc(human_bytes(r['rx'])), esc(human_bytes(r['tx']))))
        inner = ('<table><tr><th>下线时间</th><th>协议</th><th>账号</th><th>来源 IP</th>'
                 '<th>隧道 IP</th><th>在线时长</th><th>↓ 接收</th><th>↑ 发送</th></tr>%s</table>' % tr)
    inner += ('<form class="inline" method="post" action="/action" '
              'onsubmit="return confirm(\'确定清空全部连接历史?\')">'
              '<input type="hidden" name="csrf" value="{csrf}">'
              '<input type="hidden" name="action" value="sess_clear">'
              '<button class="btn sm danger" type="submit">清空历史</button></form>')
    return card('连接历史（最近 %d 条）' % limit,
                '<details><summary>展开查看历史连接</summary>%s</details>' % inner)


def _vpn_manage(proto, v):
    out = ''
    st = load_state()
    if proto in ('pptp', 'l2tp'):
        out += '<div class="tip">当前接入的客户端：</div>' + sessions_table(st, proto, '-' + proto)
        users = v.get('users', [])
        rows = ''
        for i, u in enumerate(users):
            dis = bool(u.get('disabled'))
            rows += (
                '<tr><td>%s</td><td>%s</td><td>%s</td>'
                '<td><form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_user_toggle">'
                '<input type="hidden" name="proto" value="%s"><input type="hidden" name="idx" value="%d">'
                '<input type="hidden" name="enable" value="%s">'
                '<button class="btn sm %s" type="submit">%s</button></form> '
                '<form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_del_user">'
                '<input type="hidden" name="proto" value="%s"><input type="hidden" name="idx" value="%d">'
                '<button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                % (esc(u['user']), esc(u['pw']),
                   '<span class="badge bad">已禁用</span>' if dis else '<span class="badge ok">正常</span>',
                   proto, i, '1' if dis else '0', '' if dis else 'warn',
                   '启用' if dis else '禁用', proto, i))
        out += ('<table><tr><th>账号</th><th>密码</th><th>状态</th><th>操作</th></tr>%s</table>'
                % (rows or '<tr><td colspan="4">暂无账号</td></tr>'))
        out += ('<div class="row"><form method="post" action="/action" class="row">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_add_user">'
                '<input type="hidden" name="proto" value="%s">'
                '账号 <input name="user" size="14">密码 <input name="pw" size="14">'
                '<button class="btn sm" type="submit">添加账号</button></form></div>' % proto)
        if proto == 'l2tp':
            out += ('<div class="row"><form method="post" action="/action" class="row">'
                    '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_set_psk">'
                    '预共享密钥 PSK <input name="psk" size="30" value="%s">'
                    '<button class="btn sm" type="submit">保存 PSK</button></form></div>' % esc(v.get('psk', '')))
            out += '<div class="tip">L2TP 使用 IPsec PSK 认证，客户端需填写上面 PSK 与账号密码。服务器 %s:1701 (UDP)。</div>' % esc(wan_ip_live())
        else:
            out += '<div class="tip">PPTP 使用 MS-CHAPv2，客户端填账号密码即可。服务器 %s:1723 (TCP) + GRE。</div>' % esc(wan_ip_live())
    elif proto == 'openvpn':
        out += '<div class="tip">当前接入的客户端：</div>' + sessions_table(st, 'openvpn', '-openvpn')
        clients = v.get('clients', [])
        _host, _port, _proto = ovpn_server_endpoint()
        _net, _mask = ovpn_server_net(v)
        _srv = vpn_server_addr('openvpn', v) or '-'
        _ps, _pe = vpn_pool_range('openvpn', v)
        rows = ''
        for c in clients:
            nm = c.get('name', '')
            dis = bool(c.get('disabled'))
            ip = (c.get('ip') or '').strip()
            _ok, _msg = ovpn_static_ip_check(ip, nm, st) if ip else (True, '')
            ipform = ('<form class="inline" method="post" action="/action">'
                      '<input type="hidden" name="csrf" value="{csrf}">'
                      '<input type="hidden" name="action" value="ovpn_client_ip">'
                      '<input type="hidden" name="name" value="%s">'
                      '<input name="ip" size="13" placeholder="自动" value="%s">'
                      '<button class="btn sm" type="submit">保存</button></form>'
                      % (esc(nm), esc(ip)))
            if ip and not _ok:
                ipform += '<div class="tip bad">%s</div>' % esc(_msg)
            elif ip and _msg:
                ipform += '<div class="tip">%s</div>' % esc(_msg)
            rows += (
                '<tr><td>%s</td><td>%s</td><td>%s</td>'
                '<td><a class="btn sm" href="/ovpn-download?kind=server&amp;name=%s&amp;mode=full">导出 .ovpn</a> '
                '<a class="btn sm" href="/ovpn-download?kind=server&amp;name=%s&amp;mode=lan">仅内网版</a></td>'
                '<td><form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="ovpn_access_toggle">'
                '<input type="hidden" name="name" value="%s"><input type="hidden" name="enable" value="%s">'
                '<button class="btn sm %s" type="submit">%s</button></form> '
                '<form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_del_client">'
                '<input type="hidden" name="proto" value="openvpn"><input type="hidden" name="name" value="%s">'
                '<button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                % (esc(nm),
                   '<span class="badge bad">已禁用</span>' if dis else '<span class="badge ok">正常</span>',
                   ipform,
                   urllib.parse.quote(nm), urllib.parse.quote(nm),
                   esc(nm), '1' if dis else '0', '' if dis else 'warn',
                   '启用' if dis else '禁用', esc(nm)))
        out += ('<table><tr><th>客户端</th><th>状态</th><th>固定隧道 IP</th><th>导出配置</th><th>操作</th></tr>%s</table>'
                % (rows or '<tr><td colspan="5">暂无客户端</td></tr>'))
        out += ('<div class="row"><form method="post" action="/action" class="row">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_add_client">'
                '客户端名 <input name="name" size="14" placeholder="client1"> '
                '固定 IP <input name="ip" size="13" placeholder="可留空">'
                '<button class="btn sm" type="submit">生成客户端配置</button></form></div>')
        out += ('<div class="tip">客户端网段 <b>%s/%s</b>，服务端隧道地址 <b>%s</b>，动态池 <b>%s</b>。'
                '给客户端指定固定 IP 后，它每次连接都会拿到同一个地址（便于内网侧按 IP 做策略）；留空则由服务端动态分配。'
                '修改后若该客户端正在线，会被断开一次以便重新获取地址。</div>'
                % (esc(_net), esc(_mask), esc(_srv),
                   ('%s - %s' % (_ps, _pe)) if _ps else '自动'))
        out += ('<div class="tip">OpenVPN 监听 %s %s:%s。添加客户端后会自动签发证书；'
                '点击“导出 .ovpn”直接下载客户端配置文件（全流量版含 <code>redirect-gateway def1</code>，'
                '“仅内网版”只把内网 %s 指向隧道、不影响客户端上网）。'
                '文件名：<code>&lt;客户端名&gt;.ovpn</code> / <code>&lt;客户端名&gt;-lan.ovpn</code>。</div>'
                % (esc(_proto.upper()), esc(wan_ip_live()), esc(_port), esc(LAN_NET)))
        for c in clients:
            conf = ovpn_client_conf(c['name'])
            out += ('<details><summary>%s.ovpn（展开查看 / 复制）</summary><pre>%s</pre></details>'
                    % (esc(c['name']), esc(conf)))
        # ---- 路由推送设置: 决定客户端连上后哪些网段走隧道 ----
        _tn = []
        for _k in ('ovpn_clients', 'pptp_clients', 'l2tp_clients'):
            for _c in (st.get(_k) or []):
                for _n in nets_of(_c):
                    if _n not in _tn:
                        _tn.append(_n)
        _pr = ovpn_push_routes(st)
        out += ('<details><summary>路由推送设置（客户端连上后哪些网段走隧道）</summary>'
                '<form method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}">'
                '<input type="hidden" name="action" value="ovpn_push_save">'
                '<div><label><input type="checkbox" name="push_lan" value="1"%s> '
                '推送内网网段 <code>%s</code></label></div>'
                '<div><label><input type="checkbox" name="push_default" value="1"%s> '
                '客户端全流量走隧道（下发 <code>redirect-gateway def1</code>，会改写客户端默认网关）</label></div>'
                '<div><label><input type="checkbox" name="push_tunnels" value="1"%s> '
                '自动包含网关出向隧道的远端网段%s</label></div>'
                '<div>额外推送网段（每行一条：<code>10.10.2.0/24</code> 或 <code>10.10.2.0 255.255.255.0</code>）<br>'
                '<textarea name="push_routes" rows="4" cols="54">%s</textarea></div>'
                '<button class="btn sm" type="submit">保存并重载 OpenVPN</button></form>'
                '<div class="tip">当前下发给客户端的路由：%s；%s。</div></details>'
                % (' checked' if v.get('push_lan', True) else '',
                   esc(LAN_NET),
                   ' checked' if ovpn_push_default(st) else '',
                   ' checked' if v.get('push_tunnels') else '',
                   ('（%s）' % esc(', '.join(_tn))) if _tn else '（当前无出向隧道）',
                   esc('\n'.join(v.get('push_routes') or [])),
                   (esc(' / '.join(_pr)) if _pr else '无'),
                   '全流量已开启，客户端所有流量都走隧道' if ovpn_push_default(st)
                   else '未开启全流量，客户端只把上述网段指向隧道'))
    elif proto == 'ikev2':
        out += '<div class="tip">当前接入的客户端：</div>' + sessions_table(st, 'ikev2', '-ikev2')
        users = v.get('users', [])
        rows = ''
        for i, u in enumerate(users):
            dis = bool(u.get('disabled'))
            rows += (
                '<tr><td>%s</td><td>%s</td><td>%s</td>'
                '<td><form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_user_toggle">'
                '<input type="hidden" name="proto" value="ikev2"><input type="hidden" name="idx" value="%d">'
                '<input type="hidden" name="enable" value="%s">'
                '<button class="btn sm %s" type="submit">%s</button></form> '
                '<form class="inline" method="post" action="/action">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_del_user">'
                '<input type="hidden" name="proto" value="ikev2"><input type="hidden" name="idx" value="%d">'
                '<button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                % (esc(u['user']), esc(u['pw']),
                   '<span class="badge bad">已禁用</span>' if dis else '<span class="badge ok">正常</span>',
                   i, '1' if dis else '0', '' if dis else 'warn',
                   '启用' if dis else '禁用', i))
        out += ('<table><tr><th>账号</th><th>密码</th><th>状态</th><th>操作</th></tr>%s</table>'
                % (rows or '<tr><td colspan="4">暂无账号</td></tr>'))
        out += ('<div class="row"><form method="post" action="/action" class="row">'
                '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="vpn_add_user">'
                '<input type="hidden" name="proto" value="ikev2">'
                '账号 <input name="user" size="14">密码 <input name="pw" size="14">'
                '<button class="btn sm" type="submit">添加账号</button></form></div>')
        # CA 证书
        ca = ''
        try:
            ca = open('/etc/ipsec.d/cacerts/ca.crt').read()
        except Exception:
            ca = ''
        out += '<div class="tip">IKEv2 使用 EAP-MSCHAPv2 + 证书。服务器 %s (UDP 500/4500)。客户端需信任下列 CA 并使用账号密码连接：</div>' % esc(wan_ip_live())
        out += '<pre>%s</pre>' % esc(ca)
    elif proto == 'wireguard':
        if not v.get('priv'):
            out += ('<div class="row"><form method="post" action="/action" class="row">'
                    '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="wg_gen">'
                    '<button class="btn sm" type="submit">生成服务器密钥对</button></form></div>')
        else:
            peers = v.get('peers', [])
            out += '<div class="tip">当前接入的客户端：</div>' + sessions_table(st, 'wireguard', '-wireguard')
            rows = ''
            for i, p in enumerate(peers):
                dis = bool(p.get('disabled'))
                rows += (
                    '<tr><td>%s</td><td>%s</td><td>%s</td>'
                    '<td><form class="inline" method="post" action="/action">'
                    '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="wg_peer_toggle">'
                    '<input type="hidden" name="idx" value="%d"><input type="hidden" name="enable" value="%s">'
                    '<button class="btn sm %s" type="submit">%s</button></form> '
                    '<form class="inline" method="post" action="/action">'
                    '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="wg_del_peer">'
                    '<input type="hidden" name="idx" value="%d">'
                    '<button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                    % (esc(p.get('name', '')), esc(p.get('allowed', '')),
                       '<span class="badge bad">已禁用</span>' if dis else '<span class="badge ok">正常</span>',
                       i, '1' if dis else '0', '' if dis else 'warn',
                       '启用' if dis else '禁用', i))
            out += ('<table><tr><th>名称</th><th>AllowedIPs</th><th>状态</th><th>操作</th></tr>%s</table>'
                    % (rows or '<tr><td colspan="4">暂无对等体</td></tr>'))
            out += ('<div class="row"><form method="post" action="/action" class="row">'
                    '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="wg_add_peer">'
                    '名称 <input name="name" size="12">'
                    '对等公钥 <input name="pub" size="46" placeholder="WireGuard 客户端公钥">'
                    'AllowedIPs <input name="allowed" size="16" value="10.10.0.2/32">'
                    '<button class="btn sm" type="submit">添加对等体</button></form></div>')
            # 客户端配置
            for i, p in enumerate(peers):
                aip = p.get('allowed', '10.10.0.2/32')
                client_ip = aip.split('/')[0]
                conf = ('[Interface]\nAddress = %s\nDNS = %s\n\n'
                        '[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n'
                        ) % (client_ip + '/24', HOST, v.get('pub', ''), wan_ip_live())
                out += '<div class="tip">客户端 %s 配置</div><pre>%s</pre>' % (esc(p.get('name', '')), esc(conf))
            out += '<div class="tip">WireGuard 监听 UDP %s:51820。</div>' % esc(wan_ip_live())
    return out

# ---- 网络配置(静态路由) ----
def build_network(msg=''):
    state = load_state()
    routes = state.get('static_routes', [])
    b = ''
    if msg:
        b += '<div class="msg info">%s</div>' % esc(msg)
    # ---- WAN 口地址配置 ----
    wan_live = iface_addr_live(WAN_IF)
    wname = nm_conn_name(WAN_IF)
    wan_method = 'static' if nm_conn_get(wname, 'ipv4.method') == 'manual' else 'dhcp'
    sel_m = ('<select name="mode" onchange="var f=document.getElementById(\'wan-static\');'
             'if(f){f.style.display=(this.value==\'static\')?\'block\':\'none\';}">'
             '<option value="dhcp"%s>DHCP 自动获取</option>'
             '<option value="static"%s>静态 IP</option></select>'
             % (' selected' if wan_method != 'static' else '',
                ' selected' if wan_method == 'static' else ''))
    wan_form = ('<div class="row"><form method="post" action="/action" class="row">'
                '<input type="hidden" name="csrf" value="{csrf}">'
                '<input type="hidden" name="action" value="wan_save">'
                '获取方式 %s'
                '<div id="wan-static" style="display:%s;margin:8px 0">'
                'IP/前缀 <input name="cidr" size="18" value="%s"> '
                '网关 <input name="gw" size="15" value="%s"> '
                'DNS(逗号分隔) <input name="dns" size="30" value="%s">'
                '</div>'
                '<button class="btn sm" type="submit">保存 WAN 配置</button></form></div>'
                % (sel_m, 'block' if wan_method == 'static' else 'none',
                   esc(wan_live or ((WAN_IP or '') + '/24')), esc(WAN_GW),
                   esc(', '.join(UP_DNS))))
    b += card('WAN 口地址配置',
              '<div class="tip">接口 <b>%s</b>，当前实际地址 <b>%s</b>。保存后立即生效并持久化'
              '(经 NetworkManager 写入连接配置，重启不丢)，同时更新防火墙规则。'
              '若正通过 WAN 口远程管理本机，改错地址会导致失联——应用失败会自动回滚。</div>%s'
              % (esc(WAN_IF), esc(wan_live or '未知'), wan_form))
    # ---- LAN 口地址配置 ----
    lan_live = iface_addr_live(LAN_IF)
    lan_pfx = LAN_NET.split('/')[1] if '/' in LAN_NET else '24'
    lan_form = ('<div class="row"><form method="post" action="/action" class="row">'
                '<input type="hidden" name="csrf" value="{csrf}">'
                '<input type="hidden" name="action" value="lan_save">'
                '接口地址/前缀 <input name="lan_cidr" size="18" value="%s" placeholder="172.16.1.1/24"> '
                '<button class="btn sm" type="submit">保存 LAN 配置</button></form></div>'
                % esc(HOST + '/' + lan_pfx))
    b += card('LAN 口地址配置',
              '<div class="tip">接口 <b>%s</b>，当前实际地址 <b>%s</b>，网段 <b>%s</b>。'
              '修改后自动联动: DHCP 地址池(旧池不在新网段时按新网段重算)、dnsmasq、防火墙 NAT、'
              'Web 管理白名单。LAN 网段不可与 WAN 网段或各 VPN 网段重叠。</div>%s'
              % (esc(LAN_IF), esc(lan_live or '未知'), esc(LAN_NET), lan_form))
    # ---- VPN 内网地址分配 ----
    vpn = state.get('vpn', {})
    vrows = ''
    for pname in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
        v = vpn.get(pname, {})
        cur = v.get('local', '') or VPN_DEF_LOCAL.get(pname, '')
        auto = '-'
        note = '-'
        try:
            import ipaddress as _ipa
            n = _ipa.ip_network(cur, strict=False)
            if pname in ('openvpn', 'wireguard'):
                auto = str(_ipa.ip_address(int(n.network_address) + 1))
            elif pname == 'ikev2':
                auto = '(客户端动态获取)'
            else:
                auto = str(n.network_address)
            usable = n.num_addresses - 2 if n.num_addresses > 2 else 0
            note = '可用 %d 个地址' % usable
        except Exception:
            pass
        _ps, _pe = vpn_pool_range(pname, v)
        _conn = int(v.get('max_connections') or 100)
        _prange = '%s ~ %s' % (_ps, _pe) if _ps else '(无可用地址)'
        sval = (v.get('server') or '').strip()
        ph = '(自动)' if pname == 'ikev2' else auto
        en = v.get('enabled')
        vrows += ('<tr><td>%s %s</td>'
                  '<td><input name="local_%s" size="18" value="%s" placeholder="%s"></td>'
                  '<td><input name="srv_%s" size="16" value="%s" placeholder="%s">'
                  '<div class="tip" style="margin:2px 0 0">留空=自动 (%s)</div></td>'
                  '<td>%s</td><td>%s</td>'
                  '<td><input name="conn_%s" type="number" min="1" max="4096" value="%d" size="5"></td></tr>'
                  % (esc(VPN_LABEL.get(pname, pname)),
                     badge('已启用') if en else badge('未启用'),
                     pname, esc(cur), esc(VPN_DEF_LOCAL.get(pname, '')),
                     pname, esc(sval), esc(ph), esc(auto),
                     esc(_prange), esc(note), pname, _conn))
    vform = ('<div class="row"><form method="post" action="/action" class="row">'
             '<input type="hidden" name="csrf" value="{csrf}">'
             '<input type="hidden" name="action" value="vpn_local_save">'
             '<table><tr><th>协议</th><th>客户端地址池 (CIDR)</th>'
             '<th>服务端地址 (留空=自动)</th><th>客户端地址范围</th><th>容量</th><th>最大并发</th></tr>'
             '%s</table>'
             '<button class="btn sm" type="submit">保存 VPN 地址分配</button></form></div>' % vrows)
    b += card('VPN 内网地址分配',
              '<div class="tip">各 VPN 协议分配给客户端的内网网段(默认值见输入框占位符)。'
              '各网段之间、与 LAN/WAN 网段均不可重叠。'
              '客户端地址池的<b>地址长度</b>(CIDR 前缀)可自由调整, 实际可分配范围见“客户端地址范围”列。'
              '<b>服务端地址</b>可留空(自动: PPTP/L2TP 取网段首地址, OpenVPN/WireGuard 取网段首地址+1, '
              'IKEv2 由客户端动态获取), 也可手动指定, 必须是本网段内的 IP; '
              'PPTP/L2TP 不可填客户端池范围(.2-.254)内的地址, OpenVPN 手动指定后客户端池自动从其下一地址开始。'
              '保存时已启用的协议会自动重写服务配置并重启(在线客户端将短暂断开重连)；'
              '未启用的协议下次启用时生效。'
              'WireGuard 已有对等体的 AllowedIPs 不会自动迁移，改网段后请到“虚拟专网”页核对。'
              '<br><b>最大并发</b>(1..4096, 默认 100): 各协议同时在线客户端上限; 填写超过该协议地址池大小时会自动按池裁剪, 不会超过可用地址数。'
              'OpenVPN 经 max-clients 直接限制; PPTP 经 pptpd connections 限制(池再大也只并发此数); '
              'L2TP / IPsec(IKEv2) 无独立并发指令, 实际通过限制下发给客户端的地址池大小实现; '
              'WireGuard 为对等体模式, 此处仅记录(并发受对等体数量约束)。</div>%s'
              % vform)
    rows = ''.join(
        '<tr><td>%s</td><td>%s</td><td>%s</td>'
        '<td><form class="inline" method="post" action="/action">'
        '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="del_route">'
        '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button>'
        '</form></td></tr>' % (esc(r.get('dest', '')), esc(r.get('gw', '-')), esc(r.get('dev', '-')), i)
        for i, r in enumerate(routes))
    form = ('<div class="row"><form method="post" action="/action" class="row">'
            '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="add_route">'
            '目标网段(CIDR) <input name="dest" size="18" placeholder="10.20.0.0/24">'
            '网关 <input name="gw" size="16" placeholder="172.16.1.2">'
            '出口设备 <input name="dev" size="10" placeholder="ens34">'
            '<button class="btn sm" type="submit">添加静态路由</button></form></div>')
    b += card('静态路由', '<table><tr><th>目标网段</th><th>网关</th><th>设备</th><th>操作</th></tr>%s</table>%s'
              % (rows or '<tr><td colspan="4">暂无静态路由</td></tr>', form))
    b += card('当前系统路由表', '<pre>%s</pre>' % esc(get_routes()))
    b += '<div class="tip">静态路由会在添加时立即生效，并通过 systemd 单元在开机后自动恢复。</div>'
    return b

# ---- 防火墙 ----
def build_firewall(msg=''):
    state = load_state()
    fw = state.get('firewall', {})
    b = ''
    if msg:
        b += '<div class="msg info">%s</div>' % esc(msg)
    sel = lambda name, cur: ''.join(
        '<option value="%s"%s>%s</option>' % (v, ' selected' if v == cur else '',
                                             '允许(accept)' if v == 'accept' else '拒绝(drop)')
        for v in ['accept', 'drop'])
    pol = ('<div class="row"><form method="post" action="/action" class="row">'
           '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="fw_policy">'
           '入站(input) <select name="input">%s</select>'
           '出站(output) <select name="output">%s</select>'
           '转发(forward) <select name="forward">%s</select>'
           '<button class="btn sm" type="submit">应用策略</button></form></div>'
           % (sel('input', fw.get('input', 'accept')), sel('output', fw.get('output', 'accept')),
              sel('forward', fw.get('forward', 'accept'))))
    b += card('防火墙策略', pol)
    b += '<div class="tip">默认全部为"允许"。改为"拒绝"后，仅放行已建立连接、内网(LAN)管理流量及下方"端口放行"规则；'
    b += '出站默认保持允许以免影响 NAT 出网。修改后系统会自动重排 nftables 规则。</div>'
    pas = fw.get('port_allows', [])
    rows = ''.join(
        '<tr><td>%s</td><td>%s</td><td>%s</td>'
        '<td><form class="inline" method="post" action="/action">'
        '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="del_pa">'
        '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button>'
        '</form></td></tr>' % (esc(pa.get('iface', '')), esc(pa.get('proto', '')), esc(pa.get('port', '')), i)
        for i, pa in enumerate(pas))
    form = ('<div class="row"><form method="post" action="/action" class="row">'
            '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="add_pa">'
            '接口 <select name="iface"><option value="wan">WAN(外网)</option><option value="lan">LAN(内网)</option></select>'
            '协议 <select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>'
            '端口 <input name="port" size="6">'
            '<button class="btn sm" type="submit">添加端口放行</button></form></div>')
    b += card('端口放行 (入站允许)', '<table><tr><th>接口</th><th>协议</th><th>端口</th><th>操作</th></tr>%s</table>%s'
              % (rows or '<tr><td colspan="4">暂无放行规则</td></tr>', form))
    b += '<div class="tip">端口放行即在对应接口上允许入站访问网关本机该端口（如放开 WAN 的 22 以允许外网 SSH）。</div>'

    # ---- 拒绝规则 ----
    deny = fw.get('deny_rules', [])
    ctr = get_nft_counters('filter')
    chain_lbl = {'input': '入站(本机)', 'forward': '转发(穿越)'}
    iface_lbl = {'wan': 'WAN', 'lan': 'LAN', 'any': '任意'}
    drow = ''
    for i, r in enumerate(deny):
        h = ctr.get('d%d' % i) or {'packets': 0, 'bytes': 0}
        drow += ('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                 '<td class="num">%d / %s</td>'
                 '<td><form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}">'
                 '<input type="hidden" name="action" value="del_deny">'
                 '<input type="hidden" name="idx" value="%d">'
                 '<button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                 % (esc(chain_lbl.get(r.get('chain'), r.get('chain', ''))),
                    esc(iface_lbl.get(r.get('iface'), r.get('iface', ''))),
                    esc(r.get('src') or '任意'),
                    esc(r.get('proto', '')),
                    esc(r.get('port') or '全部'),
                    esc(r.get('desc') or '-'),
                    h['packets'], fmt_bytes(h['bytes']), i))
    dform = ('<div class="row"><form method="post" action="/action" class="row">'
             '<input type="hidden" name="csrf" value="{csrf}">'
             '<input type="hidden" name="action" value="add_deny">'
             '链 <select name="chain"><option value="input">入站(本机)</option>'
             '<option value="forward">转发(穿越)</option></select>'
             '接口 <select name="iface"><option value="wan">WAN(外网)</option>'
             '<option value="lan">LAN(内网)</option><option value="any">任意</option></select>'
             '协议 <select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option>'
             '<option value="icmp">ICMP</option><option value="all">全部</option></select>'
             '端口 <input name="port" size="6" placeholder="如 23">'
             '源地址 <input name="src" size="16" placeholder="CIDR, 可留空">'
             '备注 <input name="desc" size="12">'
             '<button class="btn sm danger" type="submit">添加拒绝规则</button></form></div>')
    b += card('拒绝规则 (DROP)',
              '<table><tr><th>链</th><th>接口</th><th>源地址</th><th>协议</th><th>端口</th>'
              '<th>备注</th><th class="num">命中(包 / 流量)</th><th>操作</th></tr>%s</table>%s'
              % (drow or '<tr><td colspan="8">暂无拒绝规则</td></tr>', dform))
    b += ('<div class="tip">拒绝规则优先于"端口放行"生效，用于封禁特定源/端口（如封 WAN 侧 23 端口、'
          '封某 IP 的全部转发流量）。系统始终保留"已建立连接"例外和内网管理口 8080 放行以防自锁；'
          '"命中"为 nftables 计数器，重载规则后归零。</div>')
    b += card('当前 nftables 规则', '<pre>%s</pre>' % esc(get_nat_rules()))
    return b

# ---- DHCP 配置管理 ----
def build_dhcp(msg=''):
    state = load_state()
    dh = state.get('dhcp', DHCP_DEF)
    b = ''
    if msg:
        b += '<div class="msg info">%s</div>' % esc(msg)
    en = dh.get('enabled', True)
    sel_en = '<option value="1"%s>启用</option><option value="0"%s>停用</option>' % (
        ' selected' if en else '', '' if en else ' selected')
    form = ('<div class="row"><form method="post" action="/action" class="row">'
            '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="dhcp_save">'
            '地址池起 <input name="start" size="16" value="%s"> 止 <input name="end" size="16" value="%s"> '
            '掩码 <input name="mask" size="16" value="%s"><br>'
            '租期 <input name="lease" size="8" value="%s"> 网关 <input name="router" size="16" value="%s"> '
            'DNS(逗号分隔) <input name="dns" size="28" value="%s"><br>'
            '域名 <input name="domain" size="12" value="%s"> 状态 <select name="enabled">%s</select> '
            '<button class="btn sm" type="submit">保存 DHCP 配置</button></form></div>'
            % (esc(dh.get('start', '172.16.1.100')), esc(dh.get('end', '172.16.1.200')),
               esc(dh.get('mask', '255.255.255.0')), esc(dh.get('lease', '24h')),
               esc(dh.get('router', HOST)), esc(dh.get('dns', HOST)),
               esc(dh.get('domain', 'lan')), sel_en))
    b += card('DHCP 服务配置', form)
    b += '<div class="tip">保存后自动重启 dnsmasq 立即生效。网关/DNS 默认填 %s（由本机 dnsmasq 转发上游）。停用后 dnsmasq 仅作 DNS 服务、不再下发地址。</div>' % esc(HOST)
    leases = get_leases()
    lrows = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (esc(l['mac']), esc(l['ip']), esc(l['name'])) for l in leases)
    b += card('当前租约', '<table><tr><th>MAC</th><th>IP</th><th>主机名</th></tr>%s</table>'
              % (lrows or '<tr><td colspan="3">暂无租约</td></tr>'))
    ds = state.get('dhcp_static', [])
    drows = ''.join(
        '<tr><td>%s</td><td>%s</td><td>%s</td>'
        '<td><form class="inline" method="post" action="/action">'
        '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="del_dhcp">'
        '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button>'
        '</form></td></tr>' % (esc(d['mac']), esc(d['ip']), esc(d.get('desc', '')), i)
        for i, d in enumerate(ds))
    dform = ('<div class="row"><form method="post" action="/action" class="row">'
             '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="add_dhcp">'
             'MAC <input name="mac" size="18" placeholder="AA:BB:CC:DD:EE:FF">'
             '保留IP <input name="ip" size="14" placeholder="172.16.1.x">'
             '备注 <input name="desc" size="12">'
             '<button class="btn sm" type="submit">添加静态保留</button></form></div>')
    b += card('静态保留 (按 MAC 绑定固定 IP)', '<table><tr><th>MAC</th><th>IP</th><th>备注</th><th>操作</th></tr>%s</table>%s'
              % (drows or '<tr><td colspan="4">暂无静态保留</td></tr>', dform))
    b += card('当前 dnsmasq 配置', '<pre>%s</pre>' % esc(gen_dnsmasq(state)))
    return b

# ---- 客户端 VPN (网关拨入远端) ----
def nets_cell(c):
    """名称列下方小字: 该客户端需要走隧道的远端内网网段。"""
    t = nets_text(c)
    if not t:
        return ''
    return ('<small style="display:block;color:#8ea2b8;font-size:11px">'
            '远端网段 %s</small>' % esc(t))


def _tun_cells(kind, i, r):
    """隧道 IP / 实时速率 / 累计流量 三个单元格(id 供前端轮询刷新)。"""
    k = '%s-%d' % (kind, i)
    ip = r.get('ip') or ''
    iface = r.get('iface') or ''
    peer = r.get('peer') or ''
    if ip:
        sub = iface + ((' → %s' % peer) if peer else '')
        ip_c = '<b>%s</b><small>%s</small>' % (esc(ip), esc(sub))
        rate_c = '<b>↓ %s/s</b><small>↑ %s/s</small>' % (
            esc(fmt_bytes(r.get('rxr', 0))), esc(fmt_bytes(r.get('txr', 0))))
        tot_c = '<b>↓ %s</b><small>↑ %s</small>' % (
            esc(fmt_bytes(r.get('rx', 0))), esc(fmt_bytes(r.get('tx', 0))))
    else:
        ip_c = rate_c = tot_c = '<span class="dim">—</span>'
    return ('<td class="tun" id="ci-ip-%s">%s</td>'
            '<td class="tun num" id="ci-rate-%s">%s</td>'
            '<td class="tun num" id="ci-tot-%s">%s</td>' % (k, ip_c, k, rate_c, k, tot_c))


def _st_cell(kind, i, r):
    k = '%s-%d' % (kind, i)
    on = bool(r.get('on'))
    up = fmt_dur(r.get('up', 0))
    if on:
        state = badge('已连接')
        sub = ('<small style="display:block;color:#8ea2b8;font-size:11px">在线 %s</small>' % esc(up)) if up else ''
    elif r.get('dialing'):
        state = '<span class="badge warn">连接中</span>'
        sub = '<small style="display:block;color:#8ea2b8;font-size:11px">正在协商隧道…</small>'
    else:
        state = badge('未连接')
        sub = ('<small style="display:block;color:#d9534f;font-size:11px">%s</small>' % esc(r.get('err'))) if r.get('err') else ''
    return '<td><span id="ci-st-%s">%s%s</span></td>' % (k, state, sub)


def client_edit_form(kind, idx, c):
    """客户端“修改”表单。名称作为配置文件名不可改；密码/PSK 留空表示保持不变。"""
    label = {'ovpn': 'OpenVPN', 'l2tp': 'L2TP', 'pptp': 'PPTP'}.get(kind, kind)
    head = ('<input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="%s_client_edit">'
            '<input type="hidden" name="idx" value="%d">'
            '<input type="hidden" name="ret" value="/clients">' % (kind, idx))
    nm = '<b>%s</b> <input value="%s" size="10" readonly style="background:#eef2f6;color:#7b8b9a">' % (
        label, esc(c.get('name', '')))
    if kind == 'ovpn':
        proto = c.get('proto', 'udp')
        body = ('远端 <input name="remote" value="%s" size="20">'
                '端口 <input name="port" value="%s" size="6">'
                '协议 <select name="proto"><option value="udp"%s>UDP</option>'
                '<option value="tcp"%s>TCP</option></select> '
                '账号 <input name="user" value="%s" size="12">'
                '密码 <input type="password" name="pass" size="12" placeholder="留空不改">'
                '远端网段 <input name="nets" value="%s" size="24" placeholder="10.10.2.0/24">'
                '<label><input type="checkbox" name="redirect"%s> 全流量走隧道</label>'
                % (esc(c.get('remote', '')), esc(c.get('port', '')),
                   ' selected' if proto == 'udp' else '', ' selected' if proto == 'tcp' else '',
                   esc(c.get('user', '')), esc(nets_text(c)),
                   ' checked' if c.get('redirect') else ''))
        adv = ('<details style="margin-top:6px"><summary>替换证书 / 额外配置（留空保持不变）</summary>'
               '<div class="row" style="display:block">'
               'CA <textarea name="ca" rows="2" cols="70"></textarea><br>'
               '证书 CRT <textarea name="cert" rows="2" cols="70"></textarea><br>'
               '密钥 KEY <textarea name="key" rows="2" cols="70"></textarea><br>'
               '额外配置 <textarea name="extra" rows="2" cols="70"></textarea></div></details>')
    else:
        psk = ''
        if kind == 'l2tp':
            psk = ('PSK <input name="psk" size="20" placeholder="留空不改"> ')
        body = ('远端服务器 <input name="server" value="%s" size="20"> '
                '%s账号 <input name="user" value="%s" size="12"> '
                '密码 <input type="password" name="pass" size="12" placeholder="留空不改"> '
                '远端网段 <input name="nets" value="%s" size="24" placeholder="10.10.2.0/24">'
                '<label><input type="checkbox" name="defaultroute"%s> 默认路由</label>'
                % (esc(c.get('server', '')), psk, esc(c.get('user', '')), esc(nets_text(c)),
                   ' checked' if c.get('defaultroute') else ''))
        adv = ''
    return ('<div class="msg info" style="margin:8px 0 6px">正在修改 <b>%s</b> 客户端：%s'
            '（名称即配置文件名，不可修改；密码留空表示保持不变）</div>'
            '<form method="post" action="/action" class="row" style="margin-bottom:10px">%s%s%s'
            '<button class="btn sm" type="submit">保存修改</button>'
            '<a class="btn sm" href="/clients">取消</a></form>'
            % (label, nm, head, body, adv))


def _client_ovpn(state, rt, edit=''):
    cs = state.get('ovpn_clients', [])
    eidx = int(edit[5:]) if edit.startswith('ovpn-') and edit[5:].isdigit() else None
    rows = ''
    for i, c in enumerate(cs):
        r = rt.get(('ovpn', i), {})
        on = bool(r.get('on'))
        rows += ('<tr><td>%s%s</td><td>%s:%s</td><td>%s</td>%s%s'
                 '<td><form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="ovpn_client_toggle">'
                 '<input type="hidden" name="idx" value="%d"><input type="hidden" name="enable" value="%s">'
                 '<button class="btn sm" type="submit">%s</button></form> '
                 '<a class="btn sm" href="/clients?edit=ovpn-%d#ovpn">修改</a> '
                 '<a class="btn sm" href="/ovpn-download?kind=client&amp;name=%s">导出 .ovpn</a> '
                 '<form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="ovpn_client_del">'
                 '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                 % (esc(c.get('name', '')), nets_cell(c), esc(c.get('remote', '')), esc(c.get('port', '')),
                    esc(c.get('proto', 'udp')), _tun_cells('ovpn', i, r), _st_cell('ovpn', i, r),
                    i, '0' if on else '1', '停用' if on else '连接', i,
                    urllib.parse.quote(c.get('name', '')), i))
    form = ('<div class="row"><form method="post" action="/action" class="row">'
            '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="ovpn_client_add">'
            '名称 <input name="name" size="12" placeholder="office">'
            '远端地址 <input name="remote" size="18" placeholder="vpn.example.com">'
            '端口 <input name="port" size="6" value="1194">'
            '协议 <select name="proto"><option value="udp">UDP</option><option value="tcp">TCP</option></select> '
            '账号 <input name="user" size="12"> 密码 <input type="password" name="pass" size="12">'
            '远端网段 <input name="nets" size="24" placeholder="10.10.2.0/24">'
            '<label><input type="checkbox" name="redirect"> 全流量走隧道</label>'
            '<button class="btn sm" type="submit">添加</button></form></div>')
    adv = ('<details><summary>展开：粘贴 CA / 证书 / 密钥 / 额外配置</summary>'
           '<div class="row"><form method="post" action="/action" class="row">'
           '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="ovpn_client_add">'
           '名称 <input name="name" size="12" placeholder="office">'
           '远端地址 <input name="remote" size="18"> 端口 <input name="port" size="6" value="1194"> '
           '协议 <select name="proto"><option value="udp">UDP</option><option value="tcp">TCP</option></select><br>'
           '账号 <input name="user" size="12"> 密码 <input type="password" name="pass" size="12">'
           '远端网段 <input name="nets" size="24" placeholder="10.10.2.0/24">'
           '<label><input type="checkbox" name="redirect"> 全流量走隧道</label><br>'
           'CA(certificate) <textarea name="ca" rows="3" cols="60" placeholder="-----BEGIN CERTIFICATE-----"></textarea><br>'
           '客户端证书 CRT <textarea name="cert" rows="3" cols="60" placeholder="-----BEGIN CERTIFICATE-----"></textarea><br>'
           '客户端密钥 KEY <textarea name="key" rows="3" cols="60" placeholder="-----BEGIN PRIVATE KEY-----"></textarea><br>'
           '额外配置(每行一条) <textarea name="extra" rows="3" cols="60" placeholder="例如: float; compress lz4"></textarea><br>'
           '<button class="btn sm" type="submit">添加(含证书)</button></form></div></details>')
    imp = ('<details><summary>导入 .ovpn 配置文件（上传文件 / 粘贴内容）</summary>'
           '<div class="row"><form method="post" action="/action" enctype="multipart/form-data" class="row">'
           '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="ovpn_client_import">'
           '名称 <input name="name" size="12" placeholder="留空取文件名"> '
           '选择文件 <input type="file" name="ovpnfile" accept=".ovpn,.conf,.txt"> '
           '<label><input type="checkbox" name="connect"> 导入后立即连接</label><br>'
           '或直接粘贴配置内容 <textarea name="ovpntext" rows="6" cols="86" '
           'placeholder="client&#10;remote vpn.example.com 1194&#10;&lt;ca&gt;…&lt;/ca&gt;"></textarea><br>'
           '账号 <input name="user" size="12"> 密码 <input type="password" name="pass" size="12"> '
           '远端网段 <input name="nets" size="24" placeholder="留空则取文件内的 route">'
           '<button class="btn sm" type="submit">导入</button></form></div>'
           '<div class="tip" style="margin-top:4px">导入时会自动解析 remote / 端口 / 协议 / route 网段 / '
           'redirect-gateway / 内联证书；设备名由网关统一分配（tun10 起），cipher、tls-auth、keepalive 等其余指令原样保留，'
           '脚本类与外部文件引用的指令会被忽略并提示。</div></details>')
    inner = ''
    if eidx is not None and 0 <= eidx < len(cs):
        inner += client_edit_form('ovpn', eidx, cs[eidx])
    inner += ('<table><tr><th>名称</th><th>远端</th><th>协议</th><th>隧道 IP</th>'
              '<th>实时速率</th><th>累计流量</th><th>状态</th><th>操作</th></tr>%s</table>'
              % (rows or '<tr><td colspan="8">暂无 OpenVPN 客户端</td></tr>'))
    inner += form + imp + adv
    inner += ('<div class="tip">网关作为 OpenVPN 客户端拨入远端服务器。连接后自动分配固定隧道设备(tun10 起)，'
              '实时显示隧道 IP、收发速率与累计流量。“导出 .ovpn”会把该连接配置下载为 '
              '<code>&lt;名称&gt;-client.ovpn</code>（已去除本机 dev 编号与凭据文件路径，可直接在其它 OpenVPN 客户端导入）；'
              '“导入 .ovpn 配置文件”则反向——把现成的 .ovpn（或粘贴的配置文本）还原成本地可管理的连接。<br>'
              '<b>注意：</b>勾选“全流量走隧道”后，<b>网关自身</b>的出网流量也会改走这条隧道，'
              '并会覆盖网关的默认路由——这会让通过本网关拨入的 VPN 客户端（以及 LAN 主机）也一起被吸进隧道，'
              '若隧道对端没有回程路由就会出现“拨上 VPN 后上不了网”。仅用于访问远端内网时，'
              '<b>请不要勾选</b>，把需要走隧道的网段填在“远端网段”里即可。</div>')
    return '<div class="sub" id="ovpn"><h3>OpenVPN 客户端</h3>%s</div>' % inner


def _client_l2tp(state, rt, edit=''):
    cs = state.get('l2tp_clients', [])
    eidx = int(edit[5:]) if edit.startswith('l2tp-') and edit[5:].isdigit() else None
    rows = ''
    for i, c in enumerate(cs):
        r = rt.get(('l2tp', i), {})
        on = bool(r.get('on')) or bool(r.get('dialing'))
        rows += ('<tr><td>%s%s</td><td>%s</td><td>%s</td>%s%s'
                 '<td><form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="l2tp_client_toggle">'
                 '<input type="hidden" name="idx" value="%d"><input type="hidden" name="enable" value="%s">'
                 '<button class="btn sm" type="submit">%s</button></form> '
                 '<a class="btn sm" href="/clients?edit=l2tp-%d#l2tp">修改</a> '
                 '<form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="l2tp_client_del">'
                 '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                 % (esc(c.get('name', '')), nets_cell(c), esc(c.get('server', '')), esc(c.get('user', '')),
                    _tun_cells('l2tp', i, r), _st_cell('l2tp', i, r),
                    i, '0' if on else '1', '停用' if on else '连接', i, i))
    form = ('<div class="row"><form method="post" action="/action" class="row">'
            '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="l2tp_client_add">'
            '名称 <input name="name" size="12"> 远端服务器 <input name="server" size="18">'
            'PSK <input name="psk" size="22"> 账号 <input name="user" size="12"> 密码 <input type="password" name="pass" size="12">'
            '远端网段 <input name="nets" size="24" placeholder="10.10.2.0/24">'
            '<label><input type="checkbox" name="defaultroute"> 默认路由</label>'
            '<button class="btn sm" type="submit">添加 L2TP 客户端</button></form></div>')
    inner = ''
    if eidx is not None and 0 <= eidx < len(cs):
        inner += client_edit_form('l2tp', eidx, cs[eidx])
    inner += ('<table><tr><th>名称</th><th>服务器</th><th>账号</th><th>隧道 IP</th>'
              '<th>实时速率</th><th>累计流量</th><th>状态</th><th>操作</th></tr>%s</table>%s'
              % (rows or '<tr><td colspan="8">暂无 L2TP 客户端</td></tr>', form))
    inner += '<div class="tip">网关作为 L2TP/IPsec 客户端拨入远端（PSK + 账号密码）。PPP 拨号成功后由 pppd 钩子回传本端/对端地址，界面显示隧道 IP 与收发速率；拨号失败原因会直接显示在状态列。</div>'
    return '<div class="sub" id="l2tp"><h3>L2TP 客户端</h3>%s</div>' % inner


def _client_pptp(state, rt, edit=''):
    cs = state.get('pptp_clients', [])
    eidx = int(edit[5:]) if edit.startswith('pptp-') and edit[5:].isdigit() else None
    rows = ''
    for i, c in enumerate(cs):
        r = rt.get(('pptp', i), {})
        on = bool(r.get('on')) or bool(r.get('dialing'))
        rows += ('<tr><td>%s%s</td><td>%s</td><td>%s</td>%s%s'
                 '<td><form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="pptp_client_toggle">'
                 '<input type="hidden" name="idx" value="%d"><input type="hidden" name="enable" value="%s">'
                 '<button class="btn sm" type="submit">%s</button></form> '
                 '<a class="btn sm" href="/clients?edit=pptp-%d#pptp">修改</a> '
                 '<form class="inline" method="post" action="/action">'
                 '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="pptp_client_del">'
                 '<input type="hidden" name="idx" value="%d"><button class="btn sm danger" type="submit">删除</button></form></td></tr>'
                 % (esc(c.get('name', '')), nets_cell(c), esc(c.get('server', '')), esc(c.get('user', '')),
                    _tun_cells('pptp', i, r), _st_cell('pptp', i, r),
                    i, '0' if on else '1', '停用' if on else '连接', i, i))
    form = ('<div class="row"><form method="post" action="/action" class="row">'
            '<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="pptp_client_add">'
            '名称 <input name="name" size="12"> 远端服务器 <input name="server" size="18">'
            '账号 <input name="user" size="12"> 密码 <input type="password" name="pass" size="12">'
            '远端网段 <input name="nets" size="24" placeholder="10.10.2.0/24">'
            '<label><input type="checkbox" name="defaultroute"> 默认路由</label>'
            '<button class="btn sm" type="submit">添加 PPTP 客户端</button></form></div>')
    inner = ''
    if eidx is not None and 0 <= eidx < len(cs):
        inner += client_edit_form('pptp', eidx, cs[eidx])
    inner += ('<table><tr><th>名称</th><th>服务器</th><th>账号</th><th>隧道 IP</th>'
              '<th>实时速率</th><th>累计流量</th><th>状态</th><th>操作</th></tr>%s</table>%s'
              % (rows or '<tr><td colspan="8">暂无 PPTP 客户端</td></tr>', form))
    inner += '<div class="tip">网关作为 PPTP 客户端拨入远端（MS-CHAPv2 账号密码）。连接成功后由 pppd 钩子回传接口与隧道地址，实时刷新隧道 IP、收发速率与累计流量；拨号失败原因（如账号密码错误）会直接显示在状态列。</div>'
    return '<div class="sub" id="pptp"><h3>PPTP 客户端</h3>%s</div>' % inner


CLIENT_JS = """
(function(){
  function b(n){
    n=+n||0; var u=['B','KB','MB','GB','TB'], i=0;
    while(n>=1024 && i<4){ n/=1024; i++; }
    return (i===0 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i];
  }
  function dur(s){
    s=Math.max(0,Math.floor(+s||0));
    var d=Math.floor(s/86400); s-=d*86400;
    var h=Math.floor(s/3600); s-=h*3600;
    var m=Math.floor(s/60), sec=s-m*60;
    var core=('0'+h).slice(-2)+':'+('0'+m).slice(-2)+':'+('0'+sec).slice(-2);
    return d ? d+'\\u5929 '+core : core;
  }
  function set(id,html){ var e=document.getElementById(id); if(e) e.innerHTML=html; }
  function es(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(m){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]; }); }
  function tick(){
    var x=new XMLHttpRequest();
    x.open('GET','/clientinfo',true);
    x.onload=function(){
      if(x.status!==200) return;
      var d; try{ d=JSON.parse(x.responseText); }catch(e){ return; }
      var skew=Math.round(Date.now()/1000-(d.ts||0));
      (d.clients||[]).forEach(function(c){
        var k=c.kind+'-'+c.idx;
        if(c.ip){
          set('ci-ip-'+k,'<b>'+c.ip+'</b><small>'+(c.iface||'')+(c.peer?(' \\u2192 '+c.peer):'')+'</small>');
          set('ci-rate-'+k,'<b>\\u2193 '+b(c.rxr)+'/s</b><small>\\u2191 '+b(c.txr)+'/s</small>');
          set('ci-tot-'+k,'<b>\\u2193 '+b(c.rx)+'</b><small>\\u2191 '+b(c.tx)+'</small>');
        }else{
          set('ci-ip-'+k,'<span class="dim">\\u2014</span>');
          set('ci-rate-'+k,'<span class="dim">\\u2014</span>');
          set('ci-tot-'+k,'<span class="dim">\\u2014</span>');
        }
        var u=(c.up||0)+skew;
        var cls=c.on?'ok':(c.dialing?'warn':'bad');
        var txt=c.on?'\\u5df2\\u8fde\\u63a5':(c.dialing?'\\u8fde\\u63a5\\u4e2d':'\\u672a\\u8fde\\u63a5');
        var extra='';
        if(c.on && u>0){
          extra='<small style="display:block;color:#8ea2b8;font-size:11px">\\u5728\\u7ebf '+dur(u)+'</small>';
        }else if(c.dialing){
          extra='<small style="display:block;color:#8ea2b8;font-size:11px">\\u6b63\\u5728\\u534f\\u5546\\u96a7\\u9053\\u2026</small>';
        }else if(c.err){
          extra='<small style="display:block;color:#d9534f;font-size:11px">'+es(c.err)+'</small>';
        }
        set('ci-st-'+k,'<span class="badge '+cls+'">'+txt+'</span>'+extra);
      });
    };
    x.send();
  }
  setTimeout(tick,800);
  setInterval(tick,3000);
})();
"""


def build_clients(msg='', edit=''):
    state = load_state()
    rt = client_runtime(state)
    b = ''
    if msg:
        b += '<div class="msg info">%s</div>' % esc(msg)
    b += card('客户端 VPN（网关拨入远端）',
              '<div class="tip">以下为"客户端"模式：网关作为 VPN 客户端拨入远端服务器（站点到站点 / 出向隧道），与"虚拟专网"中的服务端模式相互独立，互不影响。'
              '连接成功后可用隧道地址访问本管理页面（见仪表盘"Web 管理登录地址"）。</div>')
    b += _client_ovpn(state, rt, edit)
    b += _client_l2tp(state, rt, edit)
    b += _client_pptp(state, rt, edit)
    b += '<script>%s</script>' % CLIENT_JS
    return b

def build_tools(tool='', target='', out='', count='4', hops='15'):
    b = ''
    b += card('网络工具（Ping / 路由跟踪）',
              '<div class="tip">在网关上直接发起诊断，用于排查到上游、内网或公网的连通性与路径。'
              '目标支持 IPv4 与域名，参数经白名单校验后以参数数组方式执行，不经过 shell。</div>')
    ping_sub = ('<div class="sub"><h3>Ping 连通性测试</h3>'
                '<form method="get" action="/tools" class="row">'
                '<input type="hidden" name="tool" value="ping">'
                '目标 <input name="target" size="26" placeholder="10.10.173.1 或 www.baidu.com" value="%s">'
                '次数 <input name="count" size="4" value="%s">'
                '<button class="btn sm" type="submit">开始 Ping</button></form>'
                '<div class="row" style="margin:6px 0 0">'
                '<a class="btn sm" href="/tools?tool=ping&amp;target=10.10.173.1">上游网关 10.10.173.1</a>'
                '<a class="btn sm" href="/tools?tool=ping&amp;target=223.5.5.5">阿里 DNS 223.5.5.5</a>'
                '<a class="btn sm" href="/tools?tool=ping&amp;target=%s">本机 LAN %s</a>'
                '</div></div>'
                % (esc(target if tool == 'ping' else ''), esc(count or '4'), esc(HOST), esc(HOST)))
    trace_sub = ('<div class="sub"><h3>路由跟踪 (Traceroute)</h3>'
                 '<form method="get" action="/tools" class="row">'
                 '<input type="hidden" name="tool" value="trace">'
                 '目标 <input name="target" size="26" placeholder="223.5.5.5" value="%s">'
                 '最大跳数 <input name="hops" size="4" value="%s">'
                 '<button class="btn sm" type="submit">开始跟踪</button></form>'
                 '<div class="row" style="margin:6px 0 0">'
                 '<a class="btn sm" href="/tools?tool=trace&amp;target=10.10.173.1">跟踪到上游网关</a>'
                 '<a class="btn sm" href="/tools?tool=trace&amp;target=223.5.5.5">跟踪到 223.5.5.5</a>'
                 '</div>'
                 '<div class="tip">使用 ICMP 模式（traceroute -n -q 1），每跳仅探测一次以加快返回；最多 30 跳。</div></div>'
                 % (esc(target if tool == 'trace' else ''), esc(hops or '15')))
    b += card('诊断入口', ping_sub + trace_sub)
    if out:
        title = {'ping': 'Ping 结果', 'trace': '路由跟踪结果'}.get(tool, '执行结果')
        b += card(title, '<pre>%s</pre>' % esc(out))
    else:
        b += '<div class="tip" style="margin-top:-6px">填写目标后点击按钮，结果将显示在本页下方。</div>'
    return b


def build_login(err='', ip=''):
    b = ''
    if err:
        b += '<div class="msg err">%s</div>' % esc(err)
    b += '<div class="card" style="max-width:380px;margin:40px auto">'
    b += '<h2>登录</h2>'
    b += ('<form method="post" action="/login">'
          '密码 <input type="password" name="pw" size="20"><br><br>'
          '<button class="btn" type="submit">登录</button></form>')
    addrs = ['http://%s:%d/' % (HOST, PORT)]
    for a in local_v4():
        if is_tunnel_if(a['iface']):
            addrs.append('http://%s:%d/' % (a['addr'], PORT))
    b += ('<div class="tip" style="margin-top:14px">可用登录地址：%s<br>'
          'VPN 客户端连接后，可直接用隧道地址登录管理页面。%s</div>'
          % ('　'.join(esc(x) for x in addrs),
             ('<br>当前来源：%s' % esc(norm_ip(ip))) if ip else ''))
    b += '</div>'
    return b

# ============ HTTP 处理 ============
class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, cookies=None, redirect=None, ctype='text/html; charset=utf-8', headers=None):
        if redirect:
            self.send_response(302)
            self.send_header('Location', redirect)
        else:
            self.send_response(code)
            self.send_header('Content-Type', ctype)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        if cookies:
            for c in cookies:
                self.send_header('Set-Cookie', c)
        self.end_headers()
        if body:
            self.wfile.write(body.encode('utf-8'))

    def _token(self):
        return get_token_from_cookie(self.headers)

    def _guard_source(self):
        """来源白名单: 内网 LAN / 活动 VPN 隧道网段 / 本机。其它来源一律 403。"""
        ip = norm_ip(self.client_address[0])
        if source_allowed(ip):
            return False
        body = ('<div class="card" style="max-width:560px;margin:40px auto"><h2>访问被拒绝</h2>'
                '<div class="tip">来源地址 <b>%s</b> 不在允许范围内。管理页面仅允许内网 LAN '
                '与已连接的 VPN 隧道网段访问。<br>如需从远端内网访问，请在仪表盘'
                '“Web 管理登录地址”中把该网段加入“额外允许网段”。</div></div>'
                % esc(ip))
        self._send(403, page('访问被拒绝', body, show_nav=False))
        return True

    def do_GET(self):
        if self._guard_source():
            return
        path = self.path.split('?', 1)[0]
        token = self._token()
        if path == '/login':
            self._send(200, page('登录', build_login(ip=self.client_address[0]), show_nav=False))
            return
        if 'logout=1' in self.path:
            if token in sessions:
                del sessions[token]
            self._send(302, '', redirect='/login', cookies=['sid=; Max-Age=0; Path=/; HttpOnly'])
            return
        if not valid_session(token):
            self._send(302, '', redirect='/login')
            return
        msg = ''
        if 'msg=' in self.path:
            msg = urllib.parse.unquote(self.path.split('msg=', 1)[1].split('&', 1)[0])
        qs = urllib.parse.parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
        def q(k, d=''):
            return (qs.get(k) or [d])[0].strip()
        if path == '/metrics':
            self._send(200, json.dumps(metrics_payload(), ensure_ascii=False),
                       ctype='application/json; charset=utf-8')
            return
        if path == '/clientinfo':
            self._send(200, json.dumps(client_info_payload(), ensure_ascii=False),
                       ctype='application/json; charset=utf-8')
            return
        if path == '/vpnsessions':
            proto = q('proto')
            if proto not in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
                proto = None
            rows = vpn_sessions(None, proto)
            self._send(200, json.dumps({
                'rows': sess_rows_html(rows, show_proto=(not proto)),
                'n': len(rows),
                'time': time.strftime('%H:%M:%S'),
            }, ensure_ascii=False), ctype='application/json; charset=utf-8')
            return
        if path == '/ovpn-download':
            # 导出 OpenVPN 配置文件(.ovpn): kind=server 服务端签发的客户端配置 / kind=client 拨号端配置
            kind = q('kind', 'server')
            if kind not in ('server', 'client'):
                kind = 'server'
            dname = q('name')
            dmode = 'lan' if q('mode') == 'lan' else 'full'
            txt, fname = ovpn_download_payload(kind, dname, dmode)
            if not txt:
                back = '/clients' if kind == 'client' else '/vpn'
                self._send(302, '', redirect=back + '?msg=' + urllib.parse.quote(
                    '导出失败：未找到“%s”的配置或证书不完整' % dname))
                return
            raw = txt.encode('utf-8')
            self._send(200, txt, ctype='application/x-openvpn-profile',
                       headers={'Content-Disposition': 'attachment; filename="%s"' % fname,
                                'Content-Length': str(len(raw)),
                                'Cache-Control': 'no-store'})
            return
        if path == '/tools':
            tool, target = q('tool'), q('target')
            out = ''
            if tool in ('ping', 'trace'):
                if is_target(target):
                    out = run_net_tool(tool, target, q('count', '4'), q('hops', '15'))
                elif target:
                    out = '目标地址非法：仅支持 IPv4 / 域名（不含空格与特殊字符）'
            body = build_tools(tool, target, out, q('count', '4'), q('hops', '15'))
            self._send(200, page('网络工具', body, path=path))
            return
        if path == '/vpn':
            body = build_vpn(msg)
        elif path == '/clients':
            body = build_clients(msg, q('edit'))
        elif path == '/dhcp':
            body = build_dhcp(msg)
        elif path == '/network':
            body = build_network(msg)
        elif path == '/firewall':
            body = build_firewall(msg)
        else:
            body = build_dashboard(msg)
        self._send(200, page({'/vpn': '虚拟专网', '/clients': '客户端', '/dhcp': 'DHCP',
                              '/network': '网络配置', '/firewall': '防火墙',
                              '/tools': '网络工具'}.get(path, '仪表盘'),
                             body.replace('{csrf}', token), path=path))
        return

    def do_POST(self):
        if self._guard_source():
            return
        length = int(self.headers.get('Content-Length', 0) or 0)
        ctype = (self.headers.get('Content-Type', '') or '')
        files = {}
        if ctype.lower().startswith('multipart/form-data'):
            # 文件上传(导入 .ovpn): 自己解析, 同时限制体积
            if length > OVPN_IMPORT_MAX:
                self._send(302, '', redirect='/clients?msg=' + urllib.parse.quote(
                    '上传内容过大（上限 %d KB）' % (OVPN_IMPORT_MAX // 1024)))
                return
            fields, files = parse_multipart(ctype, self.rfile.read(length))
            def g(k):
                return (fields.get(k, '') or '').strip()
        else:
            raw = self.rfile.read(length).decode('utf-8', 'replace')
            data = urllib.parse.parse_qs(raw)
            def g(k):
                return data.get(k, [''])[0].strip()

        path = self.path.split('?', 1)[0]
        if path == '/login':
            pw = g('pw')
            stored = load_auth()
            if checkpw(pw, stored):
                tk = new_session()
                self._send(302, '', redirect='/', cookies=['sid=%s; Max-Age=%d; Path=/; HttpOnly' % (tk, SESSION_TTL)])
            else:
                self._send(200, page('登录', build_login('密码错误', ip=self.client_address[0]),
                                     show_nav=False))
            return
        token = self._token()
        if not valid_session(token):
            self._send(302, '', redirect='/login')
            return
        if g('csrf') != token:
            self._send(302, '', redirect='/?msg=' + urllib.parse.quote('CSRF 校验失败'))
            return
        action = g('action')
        msg = self.handle_action(action, g, files)
        ret = g('ret')
        _ok = ('/', '/vpn', '/clients', '/dhcp', '/network', '/firewall', '/tools')
        if not ret:
            _rp = ''
            try:
                _rp = urllib.parse.urlparse(self.headers.get('Referer', '') or '').path
            except Exception:
                _rp = ''
            if _rp in _ok:
                ret = _rp
        _frag = ''
        if '#' in ret:
            ret, _frag = ret.split('#', 1)
            if not re.match(r'^[A-Za-z0-9_-]+$', _frag):
                _frag = ''
        if ret not in _ok:
            ret = '/'
            _frag = ''
        _loc = ret + '?msg=' + urllib.parse.quote(msg)
        if _frag:
            _loc += '#' + _frag
        self._send(302, '', redirect=_loc)

    def handle_action(self, action, g, files=None):
        """files: multipart 上传的文件 {'name': {'filename':.., 'data': bytes}}。"""
        state = load_state()
        if action == 'forward':
            val = '1' if g('value') == '1' else '0'
            rc, out, err = run(['sysctl', '-w', 'net.ipv4.ip_forward=' + val])
            if rc == 0:
                try:
                    with open('/etc/sysctl.d/99-ip-forward.conf', 'w') as f:
                        f.write('net.ipv4.ip_forward = %s\n' % val)
                except Exception:
                    pass
                return 'IPv4 转发已%s' % ('开启' if val == '1' else '关闭')
            return '转发设置失败: ' + err.strip()
        elif action == 'restart':
            svc = g('svc')
            if svc in ('nftables', 'dnsmasq', 'routeweb'):
                rc, out, err = run(['systemctl', 'restart', svc])
                if rc == 0:
                    return '已重启 %s' % svc
                return '重启 %s 失败: %s' % (svc, err.strip())
            return '未知服务'
        elif action == 'add_pf':
            proto, ext, ip, iport, desc = g('proto'), g('ext_port'), g('int_ip'), g('int_port'), g('desc')
            if not (is_proto(proto) and is_port(ext) and is_ip(ip) and is_port(iport)):
                return '端口转发参数非法'
            state.setdefault('port_forwards', []).append({'proto': proto, 'ext_port': ext, 'int_ip': ip, 'int_port': iport, 'desc': desc})
            save_state(state)
            rc, out, err = apply_nft(state)
            return '端口转发已添加' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'del_pf':
            try:
                idx = int(g('idx'))
                del state['port_forwards'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            rc, out, err = apply_nft(state)
            return '端口转发已删除' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'add_dhcp':
            mac, ip, desc = g('mac'), g('ip'), g('desc')
            if not (is_mac(mac) and is_ip(ip)):
                return 'MAC 或 IP 非法'
            state.setdefault('dhcp_static', []).append({'mac': mac, 'ip': ip, 'desc': desc})
            save_state(state)
            rc, out, err = apply_dnsmasq(state)
            return '静态保留已添加' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'del_dhcp':
            try:
                idx = int(g('idx'))
                del state['dhcp_static'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            rc, out, err = apply_dnsmasq(state)
            return '静态保留已删除' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'chpw':
            old, new = g('oldpw'), g('newpw')
            stored = load_auth()
            if not checkpw(old, stored):
                return '旧密码错误'
            if len(new) < 6:
                return '新密码至少 6 位'
            save_auth(hashpw(new))
            return '密码已修改'
        # ---- 静态路由 ----
        elif action == 'add_route':
            dest, gw, dev = g('dest'), g('gw'), g('dev')
            if not is_cidr(dest):
                return '目标网段格式非法(需 CIDR, 如 10.20.0.0/24)'
            if gw and not is_ip(gw):
                return '网关 IP 非法'
            state.setdefault('static_routes', []).append({'dest': dest, 'gw': gw, 'dev': dev})
            save_state(state)
            apply_routes(state)
            return '静态路由已添加'
        elif action == 'del_route':
            try:
                idx = int(g('idx'))
                r = state['static_routes'][idx]
                del state['static_routes'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            # 从内核移除该路由, 避免残留
            args = ['ip', 'route', 'del', r.get('dest', '')]
            if r.get('gw') and is_ip(r['gw']):
                args += ['via', r['gw']]
            if r.get('dev'):
                args += ['dev', r['dev']]
            run(args)
            apply_routes(state)
            return '静态路由已删除'
        # ---- 防火墙 ----
        elif action == 'fw_policy':
            fw = state.setdefault('firewall', {})
            if g('input') in ('accept', 'drop'):
                fw['input'] = g('input')
            if g('output') in ('accept', 'drop'):
                fw['output'] = g('output')
            if g('forward') in ('accept', 'drop'):
                fw['forward'] = g('forward')
            save_state(state)
            rc, out, err = apply_nft(state)
            return '防火墙策略已应用' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'add_pa':
            iface, proto, port = g('iface'), g('proto'), g('port')
            if iface not in ('wan', 'lan') or not is_proto(proto) or not is_port(port):
                return '端口放行参数非法'
            state.setdefault('firewall', {}).setdefault('port_allows', []).append({'iface': iface, 'proto': proto, 'port': port})
            save_state(state)
            rc, out, err = apply_nft(state)
            return '端口放行已添加' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'del_pa':
            try:
                idx = int(g('idx'))
                del state['firewall']['port_allows'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            rc, out, err = apply_nft(state)
            return '端口放行已删除' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'add_deny':
            chain, iface, proto = g('chain'), g('iface'), g('proto')
            port, src, desc = g('port'), g('src'), g('desc')
            if chain not in ('input', 'forward') or iface not in ('wan', 'lan', 'any') \
                    or proto not in ('tcp', 'udp', 'icmp', 'all'):
                return '拒绝规则参数非法'
            if src:
                if is_ip(src):
                    src = src + '/32'
                elif not is_cidr(src):
                    return '源地址须为 IP 或 CIDR 格式'
            if proto in ('tcp', 'udp'):
                if not is_port(port):
                    return '端口非法'
            else:
                port = ''
            if chain == 'input' and iface == 'lan' and proto == 'tcp' and port == str(PORT):
                return '不能拒绝内网管理端口 %d' % PORT
            if iface in ('lan', 'any') and proto == 'all' and not src and chain == 'input':
                return '拒绝该范围全部入站会切断管理，已阻止'
            rules = state.setdefault('firewall', {}).setdefault('deny_rules', [])
            for r in rules:
                if (r.get('chain'), r.get('iface'), r.get('proto'), r.get('port'), r.get('src')) == \
                        (chain, iface, proto, port, src):
                    return '已存在相同的拒绝规则'
            rules.append({'chain': chain, 'iface': iface, 'proto': proto, 'port': port,
                          'src': src, 'desc': desc[:40]})
            save_state(state)
            rc, out, err = apply_nft(state)
            return '拒绝规则已添加' if rc == 0 else '应用失败: ' + err.strip()
        elif action == 'del_deny':
            try:
                idx = int(g('idx'))
                del state['firewall']['deny_rules'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            rc, out, err = apply_nft(state)
            return '拒绝规则已删除' if rc == 0 else '应用失败: ' + err.strip()
        # ---- VPN ----
        elif action == 'vpn_install':
            proto = g('proto')
            if proto not in VPN_PKGS:
                return '未知协议'
            rc, out, err = run(['bash', '-c', 'DEBIAN_FRONTEND=noninteractive apt-get install -y %s' % VPN_PKGS[proto]])
            if rc == 0:
                return '%s 安装完成' % VPN_LABEL[proto]
            return '安装失败: ' + err.strip()[:200]
        elif action == 'vpn_toggle':
            proto = g('proto')
            if proto not in VPN_DEF_LOCAL:
                return '未知协议'
            if not vpn_installed(proto):
                return '请先安装 %s' % VPN_LABEL[proto]
            enable = g('enable') == '1'
            state['vpn'][proto]['enabled'] = enable
            save_state(state)
            rc, out, err = apply_vpn(state, proto)
            return ('%s 已%s' % (VPN_LABEL[proto], '启用' if enable else '停用')) if rc == 0 else (err.strip().replace('\n', ' ') or '应用失败')
        elif action == 'vpn_add_user':
            proto = g('proto')
            user, pw = g('user'), g('pw')
            if proto not in ('pptp', 'l2tp', 'ikev2'):
                return '不支持'
            if not (is_vpn_user(user) and is_vpn_pw(pw)):
                return '账号/密码含非法字符'
            state['vpn'][proto].setdefault('users', []).append({'user': user, 'pw': pw})
            save_state(state)
            if proto == 'ikev2':
                gen_ipsec(state)
                run(['systemctl', 'restart', 'strongswan'])
            else:
                _write_chap_secrets(state)
                run(['systemctl', 'restart', 'pptpd' if proto == 'pptp' else 'xl2tpd'])
            return '账号已添加'
        elif action == 'vpn_del_user':
            proto = g('proto')
            try:
                idx = int(g('idx'))
                del state['vpn'][proto]['users'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            if proto == 'ikev2':
                gen_ipsec(state)
                run(['systemctl', 'restart', 'strongswan'])
            else:
                _write_chap_secrets(state)
                run(['systemctl', 'restart', 'pptpd' if proto == 'pptp' else 'xl2tpd'])
            return '账号已删除'
        elif action == 'vpn_set_psk':
            psk = g('psk')
            if not is_psk(psk):
                return 'PSK 非法(8-64位, 仅限安全字符)'
            state['vpn']['l2tp']['psk'] = psk
            save_state(state)
            gen_ipsec(state)
            run(['systemctl', 'restart', 'strongswan'])
            return 'PSK 已保存'
        elif action == 'vpn_add_client':
            name = g('name')
            ip = g('ip').strip()
            if not re.match(r'^[A-Za-z0-9_-]{1,32}$', name):
                return '客户端名非法'
            if any(c.get('name') == name for c in state['vpn']['openvpn'].get('clients', [])):
                return '客户端名已存在'
            if ip:
                ok, msg = ovpn_static_ip_check(ip, name, state)
                if not ok:
                    return msg
            if not vpn_installed('openvpn'):
                return '请先安装 OpenVPN'
            state['vpn']['openvpn'].setdefault('clients', []).append({'name': name, 'ip': ip})
            save_state(state)
            ovpn_client_cert(name)
            ovpn_write_ccd(name, {'name': name, 'ip': ip}, state)
            return '客户端 %s 配置已生成%s' % (name, ('，固定 IP %s' % ip) if ip else '')
        elif action == 'vpn_del_client':
            name = g('name')
            try:
                state['vpn']['openvpn']['clients'] = [c for c in state['vpn']['openvpn'].get('clients', []) if c['name'] != name]
            except Exception:
                return '删除失败'
            save_state(state)
            try:
                _p = ovpn_ccd_path(name)
                if os.path.exists(_p):
                    os.remove(_p)
            except Exception:
                pass
            return '客户端 %s 已移除(证书文件仍保留于服务器)' % name
        elif action == 'ovpn_push_save':
            # OpenVPN 服务端: 路由推送设置(客户端连上后哪些网段走隧道)
            v = state['vpn']['openvpn']
            if not v.get('enabled'):
                return 'OpenVPN 未启用'
            v['push_lan'] = (g('push_lan') == '1')
            v['push_default'] = (g('push_default') == '1')
            v['push_tunnels'] = (g('push_tunnels') == '1')
            routes, bad = [], []
            for line in (g('push_routes') or '').splitlines():
                line = line.strip()
                if not line:
                    continue
                net = line
                if not is_cidr(net):
                    parts = line.split()
                    if len(parts) == 2:                       # 10.0.0.0 255.255.255.0
                        net = mask_to_cidr(parts[0], parts[1])
                    elif len(parts) == 1 and is_ip(parts[0]):  # 单个 IP
                        net = parts[0] + '/32'
                if not is_cidr(net):
                    bad.append(line)
                    continue
                if net not in routes:
                    routes.append(net)
            if bad:
                return '以下网段无效，未保存：' + '，'.join(bad[:5])
            if not v['push_default'] and not routes and not v['push_lan'] and not v['push_tunnels']:
                return '未开启全流量且没有任何推送网段，客户端连上后将无可用路由'
            v['push_routes'] = routes
            save_state(state)
            try:
                gen_ovpn_files(state)
            except Exception:
                pass
            restarted = False
            for u in VPN_UNITS.get('openvpn', []):
                if _svc_active(u):
                    run(['systemctl', 'restart', u])
                    restarted = True
                    break
            _pl = ovpn_push_routes(state)
            return ('路由推送已保存：%s%s%s'
                    % ('下发网段 ' + '、'.join(_pl) if _pl else '不下发任何网段',
                       '，客户端全流量走隧道' if v['push_default'] else '，客户端仅上述网段走隧道',
                       '；OpenVPN 已重载，在线客户端需重连一次' if restarted else ''))

        elif action == 'ovpn_client_ip':
            name = g('name')
            ip = g('ip').strip()
            tgt = None
            for c in state['vpn']['openvpn'].get('clients', []):
                if c.get('name') == name:
                    tgt = c
                    break
            if tgt is None:
                return '客户端不存在'
            if ip:
                ok, msg = ovpn_static_ip_check(ip, name, state)
                if not ok:
                    return msg
            if ip == (tgt.get('ip') or '').strip():
                return '固定 IP 未变化'
            tgt['ip'] = ip
            save_state(state)
            ovpn_write_ccd(name, tgt, state)
            # 固定 IP 会让动态池随之收缩(server.conf), 必须重载服务才生效
            restarted = ''
            try:
                if gen_ovpn_files(state):
                    for u in VPN_UNITS.get('openvpn', []):
                        if _svc_active(u):
                            run(['systemctl', 'restart', u])
                            restarted = '；服务已重载，在线客户端将重新连接'
                            break
            except Exception:
                pass
            kicked = ''
            if not restarted:
                try:
                    for s in vpn_sessions(state, 'openvpn'):
                        if s.get('user') == name:
                            sess_kick('openvpn', name)
                            kicked = '；该客户端当前在线，已断开以便重新获取地址'
                            break
                except Exception:
                    pass
            if ip:
                return '客户端 %s 固定 IP 已设为 %s%s' % (name, ip, restarted or kicked)
            return '客户端 %s 已改为自动分配%s' % (name, restarted or kicked)
        elif action == 'wg_gen':
            priv, pub = wg_gen_keys()
            if not priv or not pub:
                return '生成密钥失败(请确认 wireguard 已安装)'
            state['vpn']['wireguard']['priv'] = priv
            state['vpn']['wireguard']['pub'] = pub
            save_state(state)
            return 'WireGuard 密钥对已生成'
        elif action == 'wg_add_peer':
            name, pub, allowed = g('name'), g('pub'), g('allowed')
            if not (re.match(r'^[A-Za-z0-9_-]{1,32}$', name) and is_wg_key(pub) and is_cidr(allowed)):
                return '对等体参数非法'
            peers = state['vpn']['wireguard'].setdefault('peers', [])
            if any(p.get('name') == name for p in peers):
                return '对等体名称已存在'
            if any(p.get('allowed') == allowed for p in peers):
                return '该 AllowedIPs 已被其它对等体占用'
            peers.append({'name': name, 'pub': pub, 'allowed': allowed})
            save_state(state)
            gen_wg_files(state)
            run(['systemctl', 'restart', 'wg-quick@wg0'])
            return '对等体已添加'
        elif action == 'wg_del_peer':
            try:
                idx = int(g('idx'))
                del state['vpn']['wireguard']['peers'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            gen_wg_files(state)
            run(['systemctl', 'restart', 'wg-quick@wg0'])
            return '对等体已删除'
        # ---- DHCP 配置管理 ----
        elif action == 'dhcp_save':
            dh = state.setdefault('dhcp', dict(DHCP_DEF))
            start, end = g('start'), g('end')
            mask, lease = g('mask'), g('lease')
            router, dns, domain = g('router'), g('dns'), g('domain')
            if not (is_ip(start) and is_ip(end) and is_ip(mask)):
                return '地址池/IP/掩码非法'
            if not re.match(r'^[0-9]+[smhd]?$', lease):
                return '租期格式非法(如 24h/infinite)'
            if router and not is_ip(router):
                return '网关 IP 非法'
            for dnss in [x.strip() for x in dns.split(',') if x.strip()]:
                if not is_ip(dnss):
                    return 'DNS IP 非法: ' + dnss
            dh['start'] = start
            dh['end'] = end
            dh['mask'] = mask
            dh['lease'] = lease
            dh['router'] = router
            dh['dns'] = dns
            dh['domain'] = domain
            dh['enabled'] = g('enabled') == '1'
            save_state(state)
            rc, out, err = apply_dnsmasq(state)
            return 'DHCP 配置已保存' if rc == 0 else '应用失败: ' + err.strip()
        # ---- 客户端 VPN: OpenVPN ----
        elif action == 'ovpn_client_add':
            name = g('name')
            remote = g('remote')
            if not re.match(r'^[A-Za-z0-9_.-]{1,32}$', name):
                return '名称非法'
            if not remote:
                return '远端地址不能为空'
            port = g('port') or '1194'
            if not is_port(port):
                return '端口非法'
            proto = g('proto') if g('proto') in ('udp', 'tcp') else 'udp'
            try:
                nets = norm_nets(g('nets'))
            except ValueError as e:
                return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            c = {'name': name, 'remote': safe_file(remote), 'port': port, 'proto': proto,
                 'dev': next_ovpn_dev(state), 'nets': nets,
                 'user': g('user'), 'pass': g('pass'), 'ca': g('ca'), 'cert': g('cert'),
                 'key': g('key'), 'redirect': g('redirect') == 'on', 'extra': g('extra')}
            state.setdefault('ovpn_clients', []).append(c)
            save_state(state)
            gen_ovpn_client_conf(name, c)
            return 'OpenVPN 客户端已添加(可点击连接)'
        elif action == 'ovpn_client_import':
            # 导入 .ovpn / .conf: 文件优先, 也可直接粘贴内容
            up = (files or {}).get('ovpnfile') or {}
            raw = up.get('data') or b''
            fname = (up.get('filename') or '').strip()
            txt = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else str(raw)
            if not txt.strip():
                txt, fname = g('ovpntext'), ''
            if not txt.strip():
                return '请选择 .ovpn 文件或粘贴配置内容'
            if len(txt.encode('utf-8', 'replace')) > OVPN_IMPORT_MAX:
                return '配置文件过大（上限 %d KB）' % (OVPN_IMPORT_MAX // 1024)
            if fname and not re.search(r'\.(ovpn|conf|txt)$', fname, re.I):
                return '仅支持 .ovpn / .conf 配置文件（当前文件：%s）' % fname
            name = ovpn_import_name(g('name'), fname)
            if not name:
                return '未能确定名称，请在“名称”里手填一个'
            pw = g('pass')
            if pw and not is_vpn_pw(pw):
                return '密码含非法字符'
            nets = []
            if g('nets'):
                try:
                    nets = norm_nets(g('nets'))
                except ValueError as e:
                    return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            p = ovpn_parse_profile(txt)
            c, err = ovpn_import_client(name, p, g('user'), pw, nets or None, state, fname)
            if err:
                return err
            m = '已导入“%s”：远端 %s:%s（%s）' % (name, c['remote'], c['port'], c['proto'].upper())
            if c['nets']:
                m += '，远端网段 %s' % ', '.join(c['nets'])
            if p.get('redirect'):
                m += '，全流量走隧道'
            if p.get('warnings'):
                m += '。提示：' + '；'.join(p['warnings'][:2])
            if g('connect') == 'on':
                apply_nft(state)
                ovpn_client_up(name)
                m += '（已发起连接）'
            else:
                m += '（可点“连接”启用）'
            return m
        elif action == 'ovpn_client_del':
            try:
                idx = int(g('idx'))
                c = state['ovpn_clients'][idx]
                del state['ovpn_clients'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            ovpn_client_down(c.get('name', ''))
            run(['bash', '-c', 'rm -f /etc/openvpn/client/%s.conf /etc/openvpn/client/%s.up' % (safe_file(c.get('name', '')), safe_file(c.get('name', '')))])
            write_nets_file(c.get('name', ''), [])
            return 'OpenVPN 客户端已删除'
        elif action == 'ovpn_client_toggle':
            try:
                idx = int(g('idx'))
                c = state['ovpn_clients'][idx]
            except Exception:
                return '参数错误'
            if g('enable') == '1':
                if not ovpn_dev(c):
                    c['dev'] = next_ovpn_dev(state)
                    save_state(state)
                gen_ovpn_client_conf(c.get('name', ''), c)
                apply_nft(state)
                ovpn_client_up(c.get('name', ''))
                return 'OpenVPN 客户端已发起连接'
            ovpn_client_down(c.get('name', ''))
            return 'OpenVPN 客户端已断开'
        # ---- 客户端 VPN: L2TP ----
        elif action == 'l2tp_client_add':
            name = g('name')
            server = g('server')
            if not re.match(r'^[A-Za-z0-9_.-]{1,32}$', name):
                return '名称非法'
            if not server:
                return '服务器不能为空'
            if not is_psk(g('psk')):
                return 'PSK 非法(8-64位, 仅限安全字符)'
            if not (is_vpn_user(g('user')) and is_vpn_pw(g('pass'))):
                return '账号/密码含非法字符'
            try:
                nets = norm_nets(g('nets'))
            except ValueError as e:
                return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            c = {'name': name, 'server': safe_file(server), 'psk': g('psk'), 'user': g('user'),
                 'pass': g('pass'), 'nets': nets, 'defaultroute': g('defaultroute') == 'on'}
            state.setdefault('l2tp_clients', []).append(c)
            save_state(state)
            gen_l2tp_files(state)
            run(['systemctl', 'restart', 'xl2tpd'])
            return 'L2TP 客户端已添加'
        elif action == 'l2tp_client_del':
            try:
                idx = int(g('idx'))
                c = state['l2tp_clients'][idx]
                del state['l2tp_clients'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            l2tp_client_down(c.get('name', ''))
            run(['bash', '-c', 'rm -f /etc/ppp/options.l2tp-%s' % safe_file(c.get('name', ''))])
            write_nets_file(c.get('name', ''), [])
            try:
                os.remove(ppp_log(c.get('name', '')))
            except Exception:
                pass
            gen_l2tp_files(state)
            if state['vpn']['l2tp'].get('enabled') or state['l2tp_clients']:
                run(['systemctl', 'restart', 'xl2tpd'])
            else:
                run(['systemctl', 'stop', 'xl2tpd'])
            return 'L2TP 客户端已删除'
        elif action == 'l2tp_client_toggle':
            try:
                idx = int(g('idx'))
                c = state['l2tp_clients'][idx]
            except Exception:
                return '参数错误'
            if g('enable') == '1':
                ensure_ppp_hooks()
                gen_l2tp_files(state)
                apply_nft(state)
                l2tp_client_up(c.get('name', ''))
                return 'L2TP 客户端已发起连接'
            l2tp_client_down(c.get('name', ''))
            return 'L2TP 客户端已断开'
        # ---- 客户端 VPN: PPTP ----
        elif action == 'pptp_client_add':
            name = g('name')
            server = g('server')
            if not re.match(r'^[A-Za-z0-9_.-]{1,32}$', name):
                return '名称非法'
            if not server:
                return '服务器不能为空'
            if not (is_vpn_user(g('user')) and is_vpn_pw(g('pass'))):
                return '账号/密码含非法字符'
            try:
                nets = norm_nets(g('nets'))
            except ValueError as e:
                return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            c = {'name': name, 'server': safe_file(server), 'user': g('user'), 'pass': g('pass'),
                 'nets': nets, 'defaultroute': g('defaultroute') == 'on'}
            state.setdefault('pptp_clients', []).append(c)
            save_state(state)
            gen_pptp_client_peer(name, c)
            return 'PPTP 客户端已添加(可点击连接)'
        elif action == 'pptp_client_del':
            try:
                idx = int(g('idx'))
                c = state['pptp_clients'][idx]
                del state['pptp_clients'][idx]
            except Exception:
                return '删除失败'
            save_state(state)
            pptp_client_down(c.get('name', ''))
            run(['bash', '-c', 'rm -f /etc/ppp/peers/%s' % safe_file(c.get('name', ''))])
            write_nets_file(c.get('name', ''), [])
            try:
                os.remove(ppp_log(c.get('name', '')))
            except Exception:
                pass
            return 'PPTP 客户端已删除'
        elif action == 'pptp_client_toggle':
            try:
                idx = int(g('idx'))
                c = state['pptp_clients'][idx]
            except Exception:
                return '参数错误'
            if g('enable') == '1':
                ensure_ppp_hooks()
                gen_pptp_client_peer(c.get('name', ''), c)
                apply_nft(state)   # 确保 LAN->隧道 的 NAT/forward 规则就位
                pptp_client_up(c.get('name', ''))
                return 'PPTP 客户端已发起连接'
            pptp_client_down(c.get('name', ''))
            return 'PPTP 客户端已断开'
        # ---- 客户端 VPN: 修改 ----
        elif action == 'pptp_client_edit':
            try:
                idx = int(g('idx'))
                c = state['pptp_clients'][idx]
            except Exception:
                return '参数错误'
            server, user, pw = g('server'), g('user'), g('pass')
            if not server:
                return '服务器不能为空'
            if not is_vpn_user(user):
                return '账号含非法字符'
            if pw and not is_vpn_pw(pw):
                return '密码含非法字符'
            try:
                nets = norm_nets(g('nets'))
            except ValueError as e:
                return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            live = pptp_client_status(c.get('name', ''))
            c['server'] = safe_file(server)
            c['user'] = user
            if pw:
                c['pass'] = pw
            c['nets'] = nets
            c['defaultroute'] = g('defaultroute') == 'on'
            save_state(state)
            ensure_ppp_hooks()
            gen_pptp_client_peer(c.get('name', ''), c)
            if live:
                pptp_client_down(c.get('name', ''))
                pptp_client_up(c.get('name', ''))
                return 'PPTP 客户端“%s”已保存，正在用新参数重新拨号' % c.get('name', '')
            return 'PPTP 客户端“%s”已保存，下次连接时生效' % c.get('name', '')
        elif action == 'l2tp_client_edit':
            try:
                idx = int(g('idx'))
                c = state['l2tp_clients'][idx]
            except Exception:
                return '参数错误'
            server, user, pw, psk = g('server'), g('user'), g('pass'), g('psk')
            if not server:
                return '服务器不能为空'
            if not is_vpn_user(user):
                return '账号含非法字符'
            if pw and not is_vpn_pw(pw):
                return '密码含非法字符'
            if psk and not is_psk(psk):
                return 'PSK 非法(8-64位, 仅限安全字符)'
            try:
                nets = norm_nets(g('nets'))
            except ValueError as e:
                return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            live = l2tp_client_status(c.get('name', ''))
            c['server'] = safe_file(server)
            c['user'] = user
            if pw:
                c['pass'] = pw
            if psk:
                c['psk'] = psk
            c['nets'] = nets
            c['defaultroute'] = g('defaultroute') == 'on'
            save_state(state)
            ensure_ppp_hooks()
            gen_l2tp_files(state)
            run(['systemctl', 'restart', 'xl2tpd'])
            return ('L2TP 客户端“%s”已保存，并已重载拨号' % c.get('name', '')) if live else \
                   ('L2TP 客户端“%s”已保存，下次连接时生效' % c.get('name', ''))
        elif action == 'ovpn_client_edit':
            try:
                idx = int(g('idx'))
                c = state['ovpn_clients'][idx]
            except Exception:
                return '参数错误'
            remote, port, pw = g('remote'), g('port') or '1194', g('pass')
            if not remote:
                return '远端地址不能为空'
            if not is_port(port):
                return '端口非法'
            if pw and not is_vpn_pw(pw):
                return '密码含非法字符'
            try:
                nets = norm_nets(g('nets'))
            except ValueError as e:
                return '远端网段非法: %s（应为 CIDR，例如 10.10.2.0/24）' % e
            live = ovpn_client_status(c.get('name', ''))
            c['remote'] = safe_file(remote)
            c['port'] = port
            c['proto'] = g('proto') if g('proto') in ('udp', 'tcp') else c.get('proto', 'udp')
            c['user'] = g('user')
            if pw:
                c['pass'] = pw
            c['redirect'] = g('redirect') == 'on'
            c['nets'] = nets
            for k in ('ca', 'cert', 'key', 'extra'):
                v = g(k)
                if v:
                    c[k] = v
            save_state(state)
            gen_ovpn_client_conf(c.get('name', ''), c)
            if live:
                ovpn_client_down(c.get('name', ''))
                ovpn_client_up(c.get('name', ''))
                return 'OpenVPN 客户端“%s”已保存，正在用新配置重连' % c.get('name', '')
            return 'OpenVPN 客户端“%s”已保存，下次连接时生效' % c.get('name', '')
        # ---- WAN / LAN / VPN 地址配置 ----
        elif action == 'wan_save':
            mode = g('mode')
            if mode not in ('dhcp', 'static'):
                return 'WAN 模式非法'
            newcfg = dict(CFG)
            if mode == 'static':
                cidr = g('cidr')
                gw = g('gw')
                dns = g('dns')
                ip, _, pfx = cidr.partition('/')
                if not is_ip(ip) or not pfx.isdigit() or int(pfx) > 32:
                    return 'WAN 地址格式非法(需 IP/前缀, 如 10.10.173.18/24)'
                if gw and not is_ip(gw):
                    return 'WAN 网关 IP 非法'
                dl = [x.strip() for x in dns.replace(',', ' ').split() if x.strip()]
                for d in dl:
                    if not is_ip(d):
                        return 'WAN DNS 含非法地址: %s' % d
                ok, detail = apply_iface_v4(WAN_IF, 'static', cidr, gw, ' '.join(dl))
                if not ok:
                    return 'WAN 配置失败: %s' % detail
                newcfg['wan_ip'] = ip
                if gw:
                    newcfg['wan_gw'] = gw
                if dl:
                    newcfg['upstream_dns'] = dl
                msg = 'WAN 口已切换为静态 %s' % cidr
            else:
                ok, detail = apply_iface_v4(WAN_IF, 'dhcp')
                if not ok:
                    return 'WAN 配置失败: %s' % detail
                newcfg['wan_ip'] = ''
                msg = 'WAN 口已切换为 DHCP (当前地址 %s)' % wan_ip_live()
            save_cfg_file(newcfg)
            reload_cfg()
            apply_nft(load_state())
            return msg
        elif action == 'lan_save':
            cidr = g('lan_cidr')
            ip, _, pfx = cidr.partition('/')
            if not is_ip(ip) or not pfx.isdigit() or not (8 <= int(pfx) <= 32):
                return 'LAN 地址格式非法(需 IP/前缀, 如 172.16.1.1/24)'
            import ipaddress
            try:
                newnet = ipaddress.ip_network('%s/%s' % (ip, pfx), strict=False)
            except Exception:
                return 'LAN 网段解析失败'
            try:
                wl = iface_addr_live(WAN_IF)
                if wl:
                    wnet = ipaddress.ip_network(wl, strict=False)
                    if wnet.overlaps(newnet):
                        return 'LAN 网段 %s 与 WAN 当前网段 %s 重叠, 拒绝保存' % (newnet, wnet)
            except Exception:
                pass
            for pname, pv in state.get('vpn', {}).items():
                lc = pv.get('local', '')
                if is_cidr(lc):
                    try:
                        if ipaddress.ip_network(lc, strict=False).overlaps(newnet):
                            return 'LAN 网段与 %s 的 VPN 网段 %s 重叠, 拒绝保存' % (VPN_LABEL.get(pname, pname), lc)
                    except Exception:
                        pass
            ok, detail = apply_iface_v4(LAN_IF, 'static', '%s/%d' % (ip, newnet.prefixlen), '', '')
            if not ok:
                return 'LAN 配置失败: %s' % detail
            newcfg = dict(CFG)
            newcfg['lan_ip'] = ip
            newcfg['lan_net'] = str(newnet)
            save_cfg_file(newcfg)
            reload_cfg()
            # DHCP 地址池联动: 旧池不在新网段内则按新网段重算
            dh = state.get('dhcp', DHCP_DEF)
            pool_reset = False
            try:
                if ipaddress.ip_address(dh.get('start', '')) not in newnet:
                    state['dhcp'] = dict(DHCP_DEF)
                    save_state(state)
                    pool_reset = True
            except Exception:
                pass
            apply_dnsmasq(state)
            apply_nft(state)
            return 'LAN 口已保存: %s (网段 %s)%s' % (
                ip, newnet, '; DHCP 地址池已按新网段重算(%s-%s)' % (
                    DHCP_DEF.get('start'), DHCP_DEF.get('end')) if pool_reset else '')
        elif action == 'vpn_local_save':
            import ipaddress
            newlocals = {}
            for pname in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
                v = g('local_' + pname)
                if not v:
                    newlocals[pname] = ''
                    continue
                if not is_cidr(v):
                    return '%s 网段格式非法(需 CIDR, 如 %s)' % (VPN_LABEL[pname], VPN_DEF_LOCAL[pname])
                try:
                    newlocals[pname] = str(ipaddress.ip_network(v, strict=False))
                except Exception:
                    return '%s 网段解析失败' % VPN_LABEL[pname]
            newservers = {}
            for pname in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
                s = (g('srv_' + pname) or '').strip()
                if not s:
                    newservers[pname] = ''
                    continue
                if not is_ip(s):
                    return '%s 服务端地址非法(需 IP 地址)' % VPN_LABEL[pname]
                lc = newlocals.get(pname, '') or state.get('vpn', {}).get(pname, {}).get('local', '')
                if not is_cidr(lc):
                    return '%s 服务端地址校验失败: 客户端网段无效' % VPN_LABEL[pname]
                try:
                    nn = ipaddress.ip_network(lc, strict=False)
                    ia = ipaddress.ip_address(s)
                except Exception:
                    return '%s 服务端地址解析失败' % VPN_LABEL[pname]
                if ia not in nn:
                    return '%s 服务端地址 %s 不在其客户端网段 %s 内' % (VPN_LABEL[pname], s, nn)
                lo = int(nn.network_address) + 2
                hi = int(nn.broadcast_address) - 1
                if pname in ('pptp', 'l2tp') and lo <= int(ia) <= hi:
                    return '%s 服务端地址 %s 落在客户端分配范围 %s-%s 内, 请改用网段首地址' % (
                        VPN_LABEL[pname], s, ipaddress.ip_address(lo), ipaddress.ip_address(hi))
                if pname == 'openvpn' and int(ia) >= hi:
                    return '%s 服务端地址 %s 过大, 客户端地址池将为空' % (VPN_LABEL[pname], s)
                newservers[pname] = s
            for pname, cv in newlocals.items():
                if not cv:
                    continue
                try:
                    _cps, _cpe = vpn_pool_range(pname, {'local': cv, 'server': newservers.get(pname, '')})
                except Exception:
                    _cps, _cpe = '', ''
                if not _cps:
                    return ('%s 网段 %s 过小, 没有可分配给客户端的地址'
                            '(请放宽地址长度, 或调整服务端地址)' % (VPN_LABEL[pname], cv))
            nets = {k: v for k, v in newlocals.items() if v}
            items = list(nets.items())
            try:
                lannet = ipaddress.ip_network(LAN_NET, strict=False)
            except Exception:
                lannet = None
            wnet = None
            try:
                wl = iface_addr_live(WAN_IF)
                if wl:
                    wnet = ipaddress.ip_network(wl, strict=False)
            except Exception:
                pass
            for i in range(len(items)):
                a = ipaddress.ip_network(items[i][1])
                if lannet and a.overlaps(lannet):
                    return '%s 网段 %s 与 LAN 网段 %s 重叠' % (VPN_LABEL[items[i][0]], items[i][1], lannet)
                if wnet and a.overlaps(wnet):
                    return '%s 网段 %s 与 WAN 网段 %s 重叠' % (VPN_LABEL[items[i][0]], items[i][1], wnet)
                for j in range(i + 1, len(items)):
                    bnet = ipaddress.ip_network(items[j][1])
                    if a.overlaps(bnet):
                        return '%s 与 %s 网段重叠(%s / %s)' % (
                            VPN_LABEL[items[i][0]], VPN_LABEL[items[j][0]], items[i][1], items[j][1])
            _conn = {}
            for pname in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
                _raw = g('conn_' + pname)
                try:
                    _n = int(_raw) if _raw not in (None, '') else 100
                    if not (1 <= _n <= 4096):
                        return '%s 最大并发需为 1..4096 整数' % VPN_LABEL[pname]
                    _conn[pname] = _n
                except Exception:
                    return '%s 最大并发格式非法 (需 1..4096 整数)' % VPN_LABEL[pname]
            changed = []
            for k, v in newlocals.items():
                if not v:
                    continue
                sv = newservers.get(k, '')
                _old = state['vpn'][k]
                same = (str(_old.get('local', '')) == str(v)
                        and str(_old.get('server') or '').strip() == str(sv).strip()
                        and int(_old.get('max_connections') or 100) == _conn[k])
                if same:
                    continue
                state['vpn'][k]['local'] = v
                state['vpn'][k]['server'] = sv
                state['vpn'][k]['max_connections'] = _conn[k]
                changed.append(k)
            if not changed:
                return 'VPN 地址分配无变化'
            save_state(state)
            applied, errs = [], []
            for k in changed:
                if state['vpn'][k].get('enabled') and vpn_installed(k):
                    rc, o, e = apply_vpn(state, k)
                    if rc == 0:
                        applied.append(VPN_LABEL[k])
                    else:
                        errs.append('%s: %s' % (VPN_LABEL[k], (e or o).strip()[:100]))
                else:
                    applied.append('%s(未启用)' % VPN_LABEL[k])
            apply_nft(state)
            msg = 'VPN 地址分配已保存: %s' % ', '.join(applied)
            if errs:
                msg += '; 失败: %s' % '; '.join(errs)
            return msg
        # ---- Web 管理访问 ----
        # ---- 在线会话管理: 断开 / 全部断开 / 账号禁用 / 历史 ----
        elif action == 'vpn_kick':
            proto = g('proto')
            if proto not in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
                return '不支持的协议'
            ok, m = sess_kick(proto, g('sid'))
            return m
        elif action == 'vpn_kick_all':
            proto = g('proto')
            if proto not in ('pptp', 'l2tp', 'openvpn', 'ikev2', 'wireguard'):
                return '不支持的协议'
            n = 0
            for x in vpn_sessions(state, proto):
                ok, _m = sess_kick(proto, x.get('id'))
                if ok:
                    n += 1
            return '已断开 %d 个连接' % n
        elif action == 'vpn_user_toggle':
            proto = g('proto')
            if proto not in ('pptp', 'l2tp', 'ikev2'):
                return '不支持'
            try:
                idx = int(g('idx'))
                u = state['vpn'][proto]['users'][idx]
            except Exception:
                return '参数错误'
            enable = g('enable') != '1'      # 传 enable=0 表示禁用
            u['disabled'] = not enable
            save_state(state)
            if proto == 'ikev2':
                gen_ipsec(state)
                run(['systemctl', 'restart', 'strongswan'])
            else:
                _write_chap_secrets(state)
                run(['systemctl', 'restart', 'pptpd' if proto == 'pptp' else 'xl2tpd'])
            if not enable:
                n = 0
                for x in vpn_sessions(state, proto):
                    if x.get('user') == u.get('user'):
                        ok, _m = sess_kick(proto, x.get('id'))
                        if ok:
                            n += 1
                return '账号已禁用（断开 %d 个在线连接）' % n
            return '账号已启用'
        elif action == 'ovpn_access_toggle':
            name = g('name')
            cs = [x for x in state['vpn']['openvpn'].get('clients', []) if x.get('name') == name]
            if not cs:
                return '参数错误'
            enable = g('enable') != '1'
            cs[0]['disabled'] = not enable
            save_state(state)
            ovpn_set_disabled(name, not enable)
            if not enable:
                for x in vpn_sessions(state, 'openvpn'):
                    if x.get('user') == name:
                        sess_kick('openvpn', x.get('id'))
                return '客户端已禁用（已断开其连接）'
            return '客户端已启用'
        elif action == 'wg_peer_toggle':
            try:
                idx = int(g('idx'))
                p = state['vpn']['wireguard']['peers'][idx]
            except Exception:
                return '参数错误'
            enable = g('enable') != '1'
            p['disabled'] = not enable
            save_state(state)
            gen_wg_files(state)
            wg_sync_peers(state)
            return '对等体已启用' if enable else '对等体已禁用（已从运行时移除）'
        elif action == 'sess_clear':
            return '连接历史已清空' if sess_history_clear() else '清空失败'
        elif action == 'web_access_save':
            extra = g('extra')
            bad = [x for x in re.split(r'[,\s]+', extra) if x and not is_cidr(x)]
            if bad:
                return '网段格式非法: ' + ', '.join(bad[:3])
            state['web_access'] = {'vpn': g('vpn') == 'on', 'extra': extra}
            save_state(state)
            return '管理访问设置已保存'
        return '未知操作'

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
            sys.stderr.flush()
        except Exception:
            pass

if __name__ == '__main__':
    os.makedirs(APP_DIR, exist_ok=True)
    load_auth()  # 确保默认密码文件存在
    # 开机恢复静态路由(若已有)
    try:
        apply_routes(load_state())
    except Exception:
        pass
    # 确保流量统计表存在(重启后计数从零开始)
    try:
        ensure_acct()
    except Exception:
        pass
    # 确保 pppd 的 ip-up/ip-down 钩子存在(用于回传隧道接口与地址)
    try:
        ensure_ppp_hooks()
    except Exception:
        pass
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer((LISTEN, PORT), Handler)
    print('RouteWeb listening on http://%s:%d (LAN %s, VPN 隧道地址按需可用)' % (LISTEN, PORT, HOST))
    httpd.serve_forever()
