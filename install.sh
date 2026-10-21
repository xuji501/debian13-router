#!/bin/bash
# 若脚本被 Windows 编辑/传输过(CRLF 行尾), 自动转换后重新执行, 避免 "invalid option name"
if grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0" 2>/dev/null
    exec bash "$0" "$@"
fi
# =============================================================================
# RouteWeb 网关一键安装脚本
#   起点火箭开发  (c) 2026   版本 V1.0.1
#   Debian 13 (trixie) / x86_64 / 双网卡
#   安装内容: NAT 转发 + DNS/DHCP + 防火墙 + 流量统计 + 五协议 VPN + Web 管理
#
#   用法:
#     ./install.sh                       交互式向导安装(出厂默认配置)
#     ./install.sh --factory             以出厂模板(factory/)安装: 完全复刻模板机
#     ./install.sh --config gw.conf      无人值守安装(读配置文件)
#     ./install.sh --factory --config gw.conf   模板打底 + 只覆盖网卡/IP
#     ./install.sh --dry-run             只打印将要执行的动作, 不改动系统
#     ./install.sh --root /tmp/t --no-apt --no-service   仅渲染文件(测试用)
#     ./install.sh --uninstall           卸载(保留 state.json 与备份)
#     ./install.sh --version             显示版本信息
# =============================================================================
set -euo pipefail

VERSION="1.0.1"
APP_VENDOR="起点火箭开发"
APP_RELDATE="2026年10月21日"
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FACTORY_DIR="$SELF_DIR/factory/rootfs"

R="/"                 # 安装根目录(测试时可指向临时目录)
DO_APT=1
DO_SVC=1
DO_NET=0
DO_NM=1
DRY=0
FORCE=0
UNINSTALL=0
FACTORY=0
CFGFILE=""
PW_ARG=""

# ---------- 输出 ----------
if [ -t 1 ]; then
    C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
    C_R=""; C_G=""; C_Y=""; C_B=""; C_D=""; C_0=""
fi
step() { printf '\n%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %s[OK]%s %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '  %s[--]%s %s\n' "$C_D" "$C_0" "$*"; }
warn() { printf '  %s[!!]%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '\n%s[错误]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '  %s$ %s%s\n' "$C_D" "$*" "$C_0"; else "$@"; fi; }

usage() {
    sed -n '7,22p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# ---------- 参数 ----------
while [ $# -gt 0 ]; do
    case "$1" in
        --config)      CFGFILE="$2"; shift 2 ;;
        --password)    PW_ARG="$2"; shift 2 ;;
        --root)        R="$2"; shift 2 ;;
        --no-apt)      DO_APT=0; shift ;;
        --no-service)  DO_SVC=0; shift ;;
        --apply-network) DO_NET=1; shift ;;
        --keep-nm)     DO_NM=0; shift ;;
        --factory)     FACTORY=1; shift ;;
        --dry-run)     DRY=1; shift ;;
        --force)       FORCE=1; shift ;;
        --uninstall)   UNINSTALL=1; shift ;;
        -V|--version)  echo "RouteWeb $VERSION  ($APP_VENDOR $APP_RELDATE)"; exit 0 ;;
        -h|--help)     usage ;;
        *) die "未知参数: $1" ;;
    esac
done
[ "$R" != "/" ] || [ "$(id -u)" = 0 ] || die "请用 root 运行: su - 或 sudo $0"

# ---------- 系统检查 ----------
check_system() {
    step "检查系统环境"
    [ -r /etc/os-release ] || die "无法读取 /etc/os-release, 不是 Debian 系统"
    . /etc/os-release
    info "系统: ${PRETTY_NAME:-unknown}"
    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID%%.*}" -lt 13 ] 2>/dev/null; then
        if [ "$FORCE" = 1 ]; then
            warn "非 Debian 13, 已按 --force 继续(可能存在包名差异)"
        else
            die "需要 Debian 13 (trixie); 确认可兼容请加 --force"
        fi
    else
        ok "系统版本符合"
    fi
    [ -f "$SELF_DIR/routeweb.py" ] || die "缺少 routeweb.py (需与本脚本同目录)"
    ok "程序文件存在: routeweb.py"
    if [ "$DO_APT" = 1 ]; then
        command -v apt-get >/dev/null || die "找不到 apt-get"
        info "检查软件源连通性"
        if [ "$DRY" = 0 ]; then
            apt-get update -qq >/dev/null 2>&1 || warn "apt-get update 失败, 请检查网络/软件源"
        fi
    fi
}

# ---------- 网卡探测 ----------
list_nics() {
    ip -br link show 2>/dev/null | awk '{print $1}' |
        grep -vE '^(lo|ppp|tun|tap|wg|docker|veth|br-|virbr)' || true
}
default_nic() {
    ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}'
}
nic_addr() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4; exit}'; }
nic_is_dhcp() {
    [ -f /run/network/ifstate ] && grep -q "^$1=" /run/network/ifstate 2>/dev/null &&	return 0
    # 简化判断: 地址来自 dhclient 租约或默认路由 proto dhcp
    ip route show default 2>/dev/null | grep -q "dev $1 proto dhcp" && return 0
    return 1
}
ask() {   # ask 变量名 "提示" 默认值
    local __v="$1" __p="$2" __d="${3:-}" __in=""
    if [ -n "$__d" ]; then
        printf '  %s [%s]: ' "$__p" "$__d" >&2
        read -r __in || true
        [ -n "$__in" ] || __in="$__d"
    else
        while [ -z "$__in" ]; do printf '  %s: ' "$__p" >&2; read -r __in || true; done
    fi
    printf -v "$__v" '%s' "$__in"
}

# ---------- 读取配置(文件优先) ----------
cfg_file_get() {
    [ -n "$CFGFILE" ] && [ -r "$CFGFILE" ] || return 1
    local k="$1"
    sed -n "s/^[[:space:]]*$k[[:space:]]*=[[:space:]]*//p" "$CFGFILE" | tail -1 |
        sed 's/[[:space:]]*$//; s/^"//; s/"$//'
}

# ---------- 出厂模板取值(--factory) ----------
# 从 factory/rootfs/etc/routeweb/config.json 读模板机的网络参数
factory_get() {
    [ "$FACTORY" = 1 ] || return 1
    local meta="$SELF_DIR/factory/FACTORY.json"
    [ -r "$FACTORY_DIR/etc/routeweb/config.json" ] || [ -r "$meta" ] || return 1
    local v
    # 先读 config.json, 再用 FACTORY.json(元信息)覆盖: 后者记录了 config 里没有的 wan_mode 等
    v=$(python3 - "$FACTORY_DIR/etc/routeweb/config.json" "$meta" "$1" <<'PY'
import json, sys
d = {}
for p in sys.argv[1:3]:
    try:
        d.update(json.load(open(p, encoding='utf-8')))
    except Exception:
        pass
if not d:
    sys.exit(1)
k = sys.argv[3]
# lan_cidr / wan_cidr 由 ip + net 合成
if k == 'lan_cidr' and 'lan_cidr' not in d:
    ip, net = d.get('lan_ip', ''), d.get('lan_net', '')
    if ip and net and '/' in net:
        print('%s/%s' % (ip, net.split('/')[1])); sys.exit(0)
if k == 'wan_cidr' and 'wan_cidr' not in d:
    ip = d.get('wan_ip', '')
    if ip: print('%s/24' % ip); sys.exit(0)
v = d.get(k, '')
if isinstance(v, list): v = ','.join(str(x) for x in v)
if v == '' or v is None: sys.exit(1)
print(v)
PY
) || return 1
    [ -n "$v" ] || return 1
    printf '%s' "$v"
}

# 取值优先级: --config 配置文件  >  出厂模板  >  交互询问
cfgget() {
    local v=""
    v=$(cfg_file_get "$1") && [ -n "$v" ] && { printf '%s' "$v"; return 0; }
    v=$(factory_get "$1") && [ -n "$v" ] && { printf '%s' "$v"; return 0; }
    return 1
}

is_ip()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] &&
            awk -F. '{for(i=1;i<=4;i++) if($i>255) exit 1}' <<<"$1"; }
is_pfx()  { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 8 ] && [ "$1" -le 30 ]; }
is_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# ---------- 向导 ----------
wizard() {
    step "网络参数配置"
    local nics; nics=$(list_nics)
    [ -n "$nics" ] || die "未发现可用网卡"
    info "可用网卡: $(echo $nics | tr '\n' ' ')"
    local def_wan; def_wan=$(default_nic)

    WAN_IF=$(cfgget wan_if) || true
    if [ -z "${WAN_IF:-}" ]; then
        ask WAN_IF "WAN 网卡(接外网/上级路由)" "$def_wan"
    fi
    # 出厂模板的网卡名在新机上可能不存在(如 ens32 -> enp1s0), 自动回退到本机检测
    if [ "$FACTORY" = 1 ] && [ -n "${WAN_IF:-}" ] && ! echo "$nics" | grep -qx "$WAN_IF"; then
        warn "模板的 WAN 网卡 $WAN_IF 在本机不存在, 改用检测到的 $def_wan"
        WAN_IF="$def_wan"
    fi
    echo "$nics" | grep -qx "$WAN_IF" || die "网卡 $WAN_IF 不存在"

    local wan_cidr; wan_cidr=$(nic_addr "$WAN_IF")
    WAN_MODE=$(cfgget wan_mode) || true
    if [ -z "${WAN_MODE:-}" ]; then
        if [ -n "$wan_cidr" ] && nic_is_dhcp "$WAN_IF"; then
            ask WAN_MODE "WAN 地址获取方式 (dhcp/static)" "dhcp"
        else
            ask WAN_MODE "WAN 地址获取方式 (dhcp/static)" "static"
        fi
    fi
    case "$WAN_MODE" in
        dhcp) ;;
        static)
            WAN_CIDR=$(cfgget wan_cidr) || true
            [ -n "${WAN_CIDR:-}" ] || ask WAN_CIDR "WAN 地址/掩码 (如 10.10.173.18/24)" "$wan_cidr"
            [[ "$WAN_CIDR" =~ ^([0-9.]+)/([0-9]+)$ ]] || die "WAN 地址格式错误: $WAN_CIDR"
            # 必须先取出 BASH_REMATCH: is_ip() 内部的正则会覆盖它
            _wip="${BASH_REMATCH[1]}"; _wpfx="${BASH_REMATCH[2]}"
            is_ip "$_wip" || die "WAN 地址非法: $WAN_CIDR"
            WAN_IP="$_wip"; WAN_PREFIX="$_wpfx"
            WAN_GW=$(cfgget wan_gw) || true
            if [ -z "${WAN_GW:-}" ]; then
                ask WAN_GW "WAN 网关" "$(echo "$WAN_IP" | awk -F. '{print $1"."$2"."$3".1"}')"
            fi
            is_ip "$WAN_GW" || die "WAN 网关非法: $WAN_GW"
            ;;
        *) die "WAN 方式只能是 dhcp 或 static" ;;
    esac

    local def_lan; def_lan=$(echo "$nics" | grep -vx "$WAN_IF" | head -1)
    LAN_IF=$(cfgget lan_if) || true
    [ -n "${LAN_IF:-}" ] || ask LAN_IF "LAN 网卡(接内网交换机)" "$def_lan"
    if [ "$FACTORY" = 1 ] && [ -n "${LAN_IF:-}" ] && ! echo "$nics" | grep -qx "$LAN_IF"; then
        warn "模板的 LAN 网卡 $LAN_IF 在本机不存在, 改用检测到的 $def_lan"
        LAN_IF="$def_lan"
    fi
    [ "$LAN_IF" != "$WAN_IF" ] || die "LAN 网卡不能与 WAN 相同"
    echo "$nics" | grep -qx "$LAN_IF" || die "网卡 $LAN_IF 不存在"

    LAN_CIDR=$(cfgget lan_cidr) || true
    [ -n "${LAN_CIDR:-}" ] || ask LAN_CIDR "LAN 网关地址/掩码" "172.16.1.1/24"
    [[ "$LAN_CIDR" =~ ^([0-9.]+)/([0-9]+)$ ]] || die "LAN 地址格式错误: $LAN_CIDR"
    _lip="${BASH_REMATCH[1]}"; _lpfx="${BASH_REMATCH[2]}"
    LAN_IP="$_lip"; LAN_PREFIX="$_lpfx"
    is_ip "$LAN_IP" && is_pfx "$LAN_PREFIX" || die "LAN 地址非法: $LAN_CIDR"

    local def_dns; def_dns=$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null |
                              grep -v '^127\.' | head -2 | paste -sd, -)
    UP_DNS=$(cfgget upstream_dns) || true
    [ -n "${UP_DNS:-}" ] || ask UP_DNS "上游 DNS(逗号分隔)" "${def_dns:-223.5.5.5,119.29.29.29}"

    WEB_PORT=$(cfgget web_port) || true
    [ -n "${WEB_PORT:-}" ] || ask WEB_PORT "Web 管理端口" "8080"
    is_port "$WEB_PORT" || die "端口非法: $WEB_PORT"

    DOMAIN=$(cfgget domain) || true
    [ -n "${DOMAIN:-}" ] || DOMAIN="lan"

    # 由 LAN 地址推算网段与 DHCP 池
    read -r LAN_NET DHCP_START DHCP_END <<<"$(python3 - "$LAN_IP" "$LAN_PREFIX" <<'PY'
import sys, ipaddress
net = ipaddress.ip_network('%s/%s' % (sys.argv[1], sys.argv[2]), strict=False)
if net.num_addresses >= 256:
    lo = net.network_address + 100
    hi = min(net.network_address + 200, net.broadcast_address - 1)
else:
    lo = net.network_address + 2
    hi = net.broadcast_address - 1
print(net, lo, hi)
PY
)"
    info "LAN 网段: $LAN_NET   DHCP 池: $DHCP_START - $DHCP_END"

    # 管理密码
    if [ -n "$PW_ARG" ]; then
        WEB_PW="$PW_ARG"; WEB_PW_GEN=0
    elif WEB_PW=$(cfgget web_password) && [ -n "${WEB_PW:-}" ]; then
        WEB_PW_GEN=0
    elif [ -n "$CFGFILE" ]; then
        WEB_PW=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(12)))')
        WEB_PW_GEN=1
    else
        echo
        info "Web 管理密码(直接回车=随机生成 12 位)"
        printf '  Web 密码: ' >&2
        read -rs WEB_PW || true; echo >&2
        if [ -z "$WEB_PW" ]; then
            WEB_PW=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(12)))')
            WEB_PW_GEN=1
        else
            printf '  再输一次: ' >&2
            local pw2; read -rs pw2 || true; echo >&2
            [ "$WEB_PW" = "$pw2" ] || die "两次密码不一致"
            WEB_PW_GEN=0
        fi
    fi

    # 摘要
    step "安装摘要"
    printf '  %-14s %s\n' "WAN 网卡" "$WAN_IF ($WAN_MODE${WAN_CIDR:+, $WAN_CIDR}${WAN_GW:+, 网关 $WAN_GW})"
    printf '  %-14s %s\n' "LAN 网卡" "$LAN_IF ($LAN_CIDR)"
    printf '  %-14s %s\n' "LAN 网段" "$LAN_NET"
    printf '  %-14s %s\n' "DHCP 池" "$DHCP_START - $DHCP_END"
    printf '  %-14s %s\n' "上游 DNS" "$UP_DNS"
    printf '  %-14s %s\n' "Web 管理" "http://$LAN_IP:$WEB_PORT/  (端口 $WEB_PORT)"
    printf '  %-14s %s\n' "管理密码" "$([ "$WEB_PW_GEN" = 1 ] && echo "(随机生成, 安装完成后显示)" || echo "********")"
    printf '  %-14s %s\n' "安装根" "$R"
    if [ -n "$CFGFILE" ] || [ "$DRY" = 1 ]; then return 0; fi
    echo
    local yn; ask yn "确认开始安装? (y/N)" "y"
    [[ "$yn" =~ ^[Yy]$ ]] || die "已取消"
}

# ---------- 依赖安装 ----------
PACKAGES="nftables dnsmasq iproute2 python3 ca-certificates openssh-server
          pptpd xl2tpd pptp-linux openvpn strongswan-swanctl wireguard-tools
          traceroute iputils-ping psmisc"

install_packages() {
    [ "$DO_APT" = 1 ] || { warn "已跳过依赖安装(--no-apt)"; return 0; }
    step "安装依赖软件包"
    local miss=""
    for p in $PACKAGES; do
        dpkg -s "$p" >/dev/null 2>&1 || miss="$miss $p"
    done
    if [ -z "$miss" ]; then ok "依赖已全部就绪"; return 0; fi
    info "待安装:$miss"
    if [ "$DRY" = 1 ]; then run apt-get install -y --no-install-recommends $miss; return 0; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $miss ||
        die "依赖安装失败, 请检查软件源"
    ok "依赖安装完成"
}

# ---------- 备份 ----------
BACKUP_DIR=""
backup_existing() {
    step "备份将被覆盖的配置"
    BACKUP_DIR="${R%/}/var/backups/routeweb/$(date +%Y%m%d-%H%M%S)"
    local files="/etc/nftables.conf /etc/nftables-acct.conf /etc/dnsmasq.conf
                 /etc/network/interfaces /etc/sysctl.d/99-routeweb.conf
                 /opt/routeweb/routeweb.py /opt/routeweb/state.json /opt/routeweb/auth.json
                 /etc/routeweb/config.json /etc/ppp/chap-secrets /etc/pptpd.conf
                 /etc/xl2tpd/xl2tpd.conf /etc/openvpn/server.conf /etc/wireguard/wg0.conf
                 /etc/systemd/system/routeweb.service /etc/systemd/system/routeweb-routes.service"
    local n=0
    for f in $files; do
        local src="${R%/}$f"
        [ -f "$src" ] || continue
        run mkdir -p "$BACKUP_DIR$(dirname "$f")"
        run cp -a "$src" "$BACKUP_DIR$f"
        n=$((n+1))
    done
    if [ "$n" = 0 ]; then info "无既有配置需要备份"; else ok "已备份 $n 个文件 -> $BACKUP_DIR"; fi
}

# ---------- 写文件 ----------
write_file() {   # write_file 绝对路径 内容
    local p="${R%/}$1"
    if [ "$DRY" = 1 ]; then info "写入 $1 ($(printf '%s' "$2" | wc -c) 字节)"; return 0; fi
    mkdir -p "$(dirname "$p")"
    printf '%s' "$2" >"$p"
}

write_config_json() {
    step "写入安装配置"
    local dns_json; dns_json=$(printf '%s' "$UP_DNS" | awk -F'[,[:space:]]+' '{s="";for(i=1;i<=NF;i++) if($i!="") s=s (s?",":"") "\""$i"\""; print "["s"]"}')
    local wan_ip_json=""
    if [ "$WAN_MODE" = "static" ]; then wan_ip_json="$WAN_IP"; fi
    local json
    json=$(cat <<EOF
{
  "wan_if": "$WAN_IF",
  "lan_if": "$LAN_IF",
  "wan_mode": "$WAN_MODE",
  "wan_ip": "${wan_ip_json:-$LAN_IP}",
  "wan_gw": "${WAN_GW:-}",
  "lan_ip": "$LAN_IP",
  "lan_net": "$LAN_NET",
  "upstream_dns": $dns_json,
  "web_port": $WEB_PORT,
  "domain": "$DOMAIN",
  "installed_at": "$(date -Iseconds)",
  "installer_version": "$VERSION"
}
EOF
)
    write_file /etc/routeweb/config.json "$json"$'\n'
    ok "配置: /etc/routeweb/config.json"
}

write_program() {
    step "安装程序"
    run mkdir -p "${R%/}/opt/routeweb"
    if [ "$DRY" = 0 ]; then
        install -m 0755 "$SELF_DIR/routeweb.py" "${R%/}/opt/routeweb/routeweb.py"
        install -m 0755 "$SELF_DIR/apply_routes.py" "${R%/}/opt/routeweb/apply_routes.py"
        find "${R%/}/opt/routeweb" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    fi
    ok "程序: /opt/routeweb/routeweb.py"

    step "初始化管理密码"
    if [ "$DRY" = 1 ]; then info "生成 auth.json"; return 0; fi
    mkdir -p "${R%/}/opt/routeweb"
    if [ -f "${R%/}/opt/routeweb/auth.json" ] && [ "$FORCE" = 0 ]; then
        info "已存在 auth.json, 保留原密码(需重置请加 --force)"
    else
        python3 - "$SELF_DIR" "$WEB_PW" "${R%/}/opt/routeweb/auth.json" <<'PY'
import sys, json
sys.path.insert(0, sys.argv[1])
import routeweb as rw
json.dump({'pw': rw.hashpw(sys.argv[2])}, open(sys.argv[3], 'w'))
PY
        ok "已写入 auth.json"
    fi

    step "初始化运行状态"
    if [ "$DRY" = 0 ] && [ ! -f "${R%/}/opt/routeweb/state.json" ]; then
        python3 - "$SELF_DIR" "${R%/}/opt/routeweb/state.json" <<'PY'
import sys, json
sys.path.insert(0, sys.argv[1])
import routeweb as rw
json.dump(rw.default_state(), open(sys.argv[2], 'w'), indent=2)
PY
        ok "已生成默认 state.json"
    else
        info "state.json 已存在或跳过"
    fi
}

# ---------- 出厂模板 ----------
# 这些文件必须由"本机"的向导结果生成, 不能照搬模板机的(网卡名/IP 会不同)
FACTORY_SKIP="
etc/routeweb/config.json
etc/network/interfaces
etc/sysctl.d/99-routeweb.conf
etc/systemd/system/routeweb.service
etc/systemd/system/routeweb-routes.service
opt/routeweb/routeweb.py
opt/routeweb/apply_routes.py
"

apply_factory() {
    [ "$FACTORY" = 1 ] || return 0
    [ -d "$FACTORY_DIR" ] || die "出厂模板不存在: $FACTORY_DIR"
    step "套用出厂模板 factory/ (完全复刻模板机配置)"
    local n=0 rel dst
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        case " $FACTORY_SKIP " in *" $rel "*) continue ;; esac
        dst="${R%/}/$rel"
        if [ "$DRY" = 1 ]; then info "模板 -> /$rel"; n=$((n + 1)); continue; fi
        mkdir -p "$(dirname "$dst")"
        cp -af "$FACTORY_DIR/$rel" "$dst"
        case "$rel" in                      # 私钥/口令文件收紧权限
            *.key|*/private/*|*/ipsec.secrets|*/chap-secrets|*/pap-secrets|*/l2tp-secrets)
                chmod 600 "$dst" 2>/dev/null || true ;;
            *) chmod 644 "$dst" 2>/dev/null || true ;;
        esac
        n=$((n + 1))
    done < <(cd "$FACTORY_DIR" && find . -type f | sed 's#^\./##' | sort)
    ok "已套用 $n 个出厂配置文件"
    reconcile_factory_state
}

# 模板机的 LAN 网段可能与本机不同 -> 重算 DHCP 池, 避免下发错误地址
reconcile_factory_state() {
    [ "$FACTORY" = 1 ] || return 0
    local sf="${R%/}/opt/routeweb/state.json"
    [ -f "$sf" ] || [ "$DRY" = 1 ] || return 0
    if [ "$DRY" = 1 ]; then info "按本机 LAN 网段校正 state.json 的 DHCP 池"; return 0; fi
    python3 - "$sf" "$LAN_IP" "$LAN_PREFIX" "$DOMAIN" <<'PY'
import ipaddress, json, sys
p, lan_ip, pfx, dom = sys.argv[1:5]
st = json.load(open(p, encoding='utf-8'))
net = ipaddress.ip_network('%s/%s' % (lan_ip, pfx), strict=False)
if net.num_addresses >= 256:
    lo = net.network_address + 100
    hi = min(net.network_address + 200, net.broadcast_address - 1)
else:
    lo = net.network_address + 2
    hi = net.broadcast_address - 1
d = st.setdefault('dhcp', {})
if d.get('router') != lan_ip:
    d.update({'enabled': d.get('enabled', True), 'start': str(lo), 'end': str(hi),
              'mask': str(net.netmask), 'lease': d.get('lease', '24h'),
              'router': lan_ip, 'dns': lan_ip, 'domain': dom})
    json.dump(st, open(p, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
    print('  [OK] DHCP 池按本机网段重算: %s - %s' % (lo, hi))
else:
    print('  [OK] state.json 网段一致, 原样保留')
PY
}

# 按出厂模板启用对应的 VPN 服务(服务端/拨号端)
factory_services() {
    [ "$FACTORY" = 1 ] || return 0
    [ "$DO_SVC" = 1 ] || return 0
    [ "$DRY" = 1 ] && { info "启用出厂模板中的 VPN 服务"; return 0; }
    step "启用出厂模板中的 VPN 服务"
    local svcs="" c nm
    [ -f "${R%/}/etc/openvpn/server.conf" ] && svcs="openvpn@server"
    for c in "${R%/}"/etc/openvpn/client/*.conf; do
        [ -e "$c" ] || continue
        nm=$(basename "$c" .conf)
        svcs="$svcs openvpn-client@$nm"
    done
    local sf="${R%/}/opt/routeweb/state.json"
    if [ -f "$sf" ]; then
        svcs="$svcs $(python3 - "$sf" <<'PY'
import json, sys
v = json.load(open(sys.argv[1], encoding='utf-8')).get('vpn', {})
m = [('pptp', 'pptpd'), ('l2tp', 'xl2tpd'), ('wireguard', 'wg-quick@wg0')]
print(' '.join(u for k, u in m if v.get(k, {}).get('enabled')))
PY
)"
        if python3 -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1],encoding='utf-8')).get('vpn',{}).get('ikev2',{}).get('enabled') else 1)" "$sf"; then
            if systemctl list-unit-files 2>/dev/null | grep -qx 'strongswan.service'; then
                svcs="$svcs strongswan"
            elif systemctl list-unit-files 2>/dev/null | grep -qx 'ipsec.service'; then
                svcs="$svcs ipsec"
            fi
        fi
    fi
    for s in $svcs; do
        systemctl enable --now "$s" >/dev/null 2>&1 && ok "已启用 $s" || warn "启用失败(可稍后手工启动): $s"
    done
}

write_network() {
    step "网络配置 (ifupdown)"
    local body
    body=$'# 由 RouteWeb 安装程序生成\nsource /etc/network/interfaces.d/*\n\nauto lo\niface lo inet loopback\n'
    body+=$'\n# WAN\nauto '"$WAN_IF"$'\niface '"$WAN_IF"' inet '"$WAN_MODE"$'\n'
    if [ "$WAN_MODE" = "static" ]; then
        body+=$'    address '"$WAN_IP/$WAN_PREFIX"$'\n    gateway '"$WAN_GW"$'\n'
        body+=$'    dns-nameservers '"${UP_DNS//,/ }"$'\n'
    fi
    body+=$'\n# LAN\nauto '"$LAN_IF"$'\niface '"$LAN_IF"' inet static\n'
    body+=$'    address '"$LAN_IP/$LAN_PREFIX"$'\n'
    write_file /etc/network/interfaces "$body"
    ok "/etc/network/interfaces (WAN=$WAN_IF/$WAN_MODE, LAN=$LAN_IF/$LAN_CIDR)"

    local sysctl
    sysctl=$'# 由 RouteWeb 安装程序生成: 开启 IPv4 转发\nnet.ipv4.ip_forward = 1\n# 关掉反向路径校验(多出口/VPN 场景必需)\nnet.ipv4.conf.all.rp_filter = 0\nnet.ipv4.conf.default.rp_filter = 0\n'
    write_file /etc/sysctl.d/99-routeweb.conf "$sysctl"
    if [ "$DRY" = 0 ] && [ "$R" = "/" ]; then
        sysctl -q -p /etc/sysctl.d/99-routeweb.conf 2>/dev/null || true
    fi
    ok "/etc/sysctl.d/99-routeweb.conf"
}

render_rules() {
    step "生成防火墙 / DNS / PPP 钩子"
    if [ "$DRY" = 1 ]; then info "渲染 nftables.conf / nftables-acct.conf / dnsmasq.conf / ppp 钩子"; return 0; fi
    python3 - "$SELF_DIR" "$R" <<'PY'
import os, sys
src, root = sys.argv[1], sys.argv[2]
sys.path.insert(0, src)
os.environ['ROUTEWEB_CONFIG'] = os.path.join(root, 'etc/routeweb/config.json')
import routeweb as rw

def w(path, txt, mode=0o644):
    p = os.path.join(root, path.lstrip('/'))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        f.write(txt)
    os.chmod(p, mode)

st = rw.load_state()
w('/etc/nftables.conf', rw.gen_nft(st))
w('/etc/nftables-acct.conf', '\n'.join(rw.gen_acct()) + '\n')
w('/etc/dnsmasq.conf', rw.gen_dnsmasq(st))
# 注意: 钩子模板需要 5 个参数, 少传会直接 TypeError
w('/etc/ppp/ip-up.d/routeweb-tunnel',
  rw.PPP_UP_HOOK % (rw.SESS_DIR, rw.SESS_DIR, rw.TUN_DIR, rw.TUN_DIR, rw.NETS_DIR), 0o755)
w('/etc/ppp/ip-down.d/routeweb-tunnel',
  rw.PPP_DOWN_HOOK % (rw.SESS_DIR, rw.SESS_DIR, rw.SESS_LOG, rw.TUN_DIR, rw.NETS_DIR), 0o755)
os.makedirs(os.path.join(root, 'etc/routeweb/nets'), exist_ok=True)
print('rendered')
PY
    [ "$?" = 0 ] || die "规则生成失败"
    ok "nftables.conf / nftables-acct.conf / dnsmasq.conf / ppp 钩子"
}

write_units() {
    step "安装 systemd 服务"
    write_file /etc/systemd/system/routeweb.service '[Unit]
Description=RouteWeb 路由管理 Web
After=network-online.target nftables.service dnsmasq.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/routeweb/routeweb.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
'
    write_file /etc/systemd/system/routeweb-routes.service '[Unit]
Description=RouteWeb 静态路由恢复
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/routeweb/apply_routes.py
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
'
    ok "routeweb.service / routeweb-routes.service"
}

enable_services() {
    [ "$DO_SVC" = 1 ] || { warn "已跳过服务启用(--no-service)"; return 0; }
    step "启用系统服务"

    # NetworkManager 与 ifupdown 抢网卡: 网关必须有确定性配置
    if [ "$DO_NM" = 1 ] && systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
        warn "检测到 NetworkManager, 已停止并禁用(避免与 ifupdown 冲突)"
        run systemctl disable --now NetworkManager 2>/dev/null || true
    fi
    # systemd-resolved 占用 53 端口会与 dnsmasq 冲突
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        warn "检测到 systemd-resolved, 已停止(53 端口让给 dnsmasq)"
        run systemctl disable --now systemd-resolved 2>/dev/null || true
        run rm -f /etc/resolv.conf
        write_file /etc/resolv.conf "$(printf 'nameserver %s\n' "${UP_DNS%%,*}")"$'\n'
    fi

    run systemctl daemon-reload
    for u in nftables dnsmasq routeweb routeweb-routes ssh; do
        run systemctl enable --quiet "$u" 2>/dev/null || warn "enable $u 失败"
    done
    for u in nftables dnsmasq routeweb routeweb-routes ssh; do
        run systemctl restart "$u" 2>/dev/null || warn "启动 $u 失败: journalctl -u $u -n 20"
    done
    sleep 1
    if [ "$DRY" = 0 ]; then
        for u in nftables dnsmasq routeweb; do
            if systemctl is-active --quiet "$u"; then ok "$u 运行中"; else warn "$u 未运行, 请查看 journalctl -u $u"; fi
        done
    fi
}

apply_network() {
    if [ "$DO_NET" = 1 ] && [ "$DRY" = 0 ]; then
        step "应用网络配置"
        warn "重配网卡会短暂中断连接(SSH 将断开, 请用 LAN 侧地址重连)"
        systemctl restart networking 2>/dev/null || ifup --all 2>/dev/null || true
        ok "已尝试重启网络"
    else
        step "网络配置生效提示"
        info "已写入 /etc/network/interfaces, 重启后生效: reboot"
        info "如需立即生效: systemctl restart networking   (会短暂断网)"
    fi
}

summary() {
    step "安装完成"
    printf '  %s管理地址%s   http://%s:%s/\n' "$C_G" "$C_0" "$LAN_IP" "$WEB_PORT"
    if [ "$FACTORY" = 1 ]; then
        printf '  %s出厂模板%s   已套用(与模板机一致的 VPN/证书/账号/防火墙配置)\n' "$C_G" "$C_0"
        printf '  %s管理密码%s   沿用出厂模板密码(首次登录后请立即修改)\n' "$C_G" "$C_0"
    elif [ "${WEB_PW_GEN:-0}" = 1 ]; then
        printf '  %s管理密码%s   %s   %s(随机生成, 请立即记录)%s\n' "$C_G" "$C_0" "$WEB_PW" "$C_Y" "$C_0"
    elif [ -z "${CFGFILE:-}" ]; then
        printf '  %s管理密码%s   你刚才输入的那个\n' "$C_G" "$C_0"
    fi
    printf '  %s网络%s       WAN %s (%s) / LAN %s (%s)\n' "$C_G" "$C_0" "$WAN_IF" "$WAN_MODE" "$LAN_IF" "$LAN_CIDR"
    printf '  %sDHCP%s       %s - %s, 网关/DNS = %s\n' "$C_G" "$C_0" "$DHCP_START" "$DHCP_END" "$LAN_IP"
    [ -n "$BACKUP_DIR" ] && printf '  %s备份%s       %s\n' "$C_G" "$C_0" "$BACKUP_DIR"
    echo
    echo "  下一步:"
    echo "    1) 内网终端用 DHCP 取址, 浏览器打开上面的管理地址"
    echo "    2) 在 Web 中按需启用 VPN 服务端(虚拟专网页)或添加客户端(客户端页)"
    echo "    3) 改网卡/IP 后需 reboot 或 systemctl restart networking"
    echo
    echo "  常用排障:"
    echo "    systemctl status routeweb dnsmasq nftables"
    echo "    journalctl -u routeweb -n 50 --no-pager"
    echo "    nft list ruleset | head -40"
    echo "    cat /etc/routeweb/config.json"
}

do_uninstall() {
    step "卸载 RouteWeb"
    [ "$(id -u)" = 0 ] || die "请用 root 运行"
    local yn; ask yn "将停止服务并删除 /opt/routeweb 与相关配置, 继续? (y/N)" "N"
    [[ "$yn" =~ ^[Yy]$ ]] || die "已取消"
    for u in routeweb routeweb-routes; do
        systemctl disable --now "$u" 2>/dev/null || true
        rm -f "/etc/systemd/system/$u.service"
    done
    systemctl daemon-reload
    rm -rf /opt/routeweb /etc/routeweb
    rm -f /etc/sysctl.d/99-routeweb.conf
    rm -f /etc/ppp/ip-up.d/routeweb-tunnel /etc/ppp/ip-down.d/routeweb-tunnel
    ok "已卸载(防火墙/DNS 配置保留, 需要时手工还原备份: ${R%/}/var/backups/routeweb/)"
}

main() {
    printf '%s\n' "============================================================"
    printf ' RouteWeb 网关安装程序 v%s   %s %s\n' "$VERSION" "$APP_VENDOR" "$APP_RELDATE"
    printf '%s\n' "============================================================"
    if [ "$UNINSTALL" = 1 ]; then do_uninstall; return; fi
    check_system
    wizard
    install_packages
    backup_existing
    write_config_json
    write_program
    apply_factory
    write_network
    render_rules
    write_units
    enable_services
    factory_services
    apply_network
    [ "$DRY" = 1 ] && { step "dry-run 结束, 未改动系统"; return; }
    summary
}

main "$@"
