# RouteWeb 网关发行版 V1.0.1

起点火箭开发 · 2026年10月21日

把一台干净的 Debian 13 变成「路由 + 防火墙 + DNS/DHCP + 五协议 VPN + Web 管理」一体机。
本版本以**现网运行中的网关为模板**固化出厂配置，装完即复刻模板机的全部设置。

---

## 一、发行形态

| 形态 | 文件名 | 适用场景 |
|---|---|---|
| 一键安装包 | `routeweb-gateway-1.0.1.tar.gz` | 通用：解压后 `./install.sh`，支持向导/无人值守/出厂模板 |
| DEB 包 | `routeweb-gateway_1.0.1_all.deb` | 内部软件源分发、批量部署、纳入资产清单 |
| ISO 镜像 | `build_iso.sh` 产出 | 全新机器裸机安装（需 Debian 13 宿主机构建） |

每个产物都附带 `.sha256` 校验文件：

```bash
sha256sum -c routeweb-gateway-1.0.1.tar.gz.sha256
```

---

## 二、三种安装方式

### 1) 交互式向导（默认出厂配置）

```bash
tar xzf routeweb-gateway-1.0.1.tar.gz
cd routeweb-gateway-1.0.1
sudo ./install.sh
```

依次询问：WAN 网卡与取址方式、LAN 网卡与地址、上游 DNS、Web 端口、管理密码。

### 2) 出厂模板（复刻模板机）— 本版本主打

```bash
sudo ./install.sh --factory
```

把 `factory/rootfs/` 下的配置按**原路径**铺进系统，包含：

- `/opt/routeweb/state.json` —— 端口转发、防火墙策略与放行、五种 VPN 服务端账号、拨号端客户端（含 ROS 隧道）、DHCP 参数、路由推送设置
- `/opt/routeweb/auth.json` —— 管理密码哈希（**沿用模板机密码**）
- `/etc/openvpn/` —— server.conf、PKI（CA + 服务端/客户端证书私钥）、CCD 固定 IP、拨号端配置
- `/etc/ppp/`、`/etc/pptpd.conf` —— PPTP 账号与选项
- `/etc/xl2tpd/`、`/etc/ipsec.conf`、`/etc/ipsec.d/` —— L2TP/IPsec 与 IKEv2
- `/etc/wireguard/` —— WireGuard 配置
- `/etc/routeweb/nets/` —— 各 VPN 客户端的远端网段

安装完成后自动按模板启用对应服务：`openvpn@server`、`openvpn-client@ROS`、ikev2 等。

网卡名或 IP 不同也不会装坏，安装器会自动处理：

- 模板里的网卡名在新机不存在 → 自动回退到本机检测到的网卡，并提示；
- LAN 网段不同 → 自动按新网段重算 DHCP 地址池（不会下发错误地址）；
- 以下文件**始终按本机生成**，不照搬模板：`config.json`、`/etc/network/interfaces`、`sysctl`、systemd 单元、主程序。

只改网卡/IP、其余照搬：

```bash
sudo ./install.sh --factory --config gw.conf
```

### 3) 无人值守（批量部署）

```bash
cp config.sample gw.conf && vi gw.conf
sudo ./install.sh --config gw.conf
```

---

## 三、安全提示（重要）

出厂模板是**现网网关的完整快照**，其中包含：

- OpenVPN / IPsec 的 **CA 私钥**与各客户端私钥（`*.key`）
- PPTP / L2TP 的账号口令（`chap-secrets`、`l2tp-secrets`）
- WireGuard 私钥、ROS 隧道的用户名口令
- Web 管理密码哈希

因此：

1. **仅限内部分发**，不要发布到公网或交付给无关第三方；
2. 装完新机后**立即**在 Web 管理里修改管理密码、轮换 VPN 账号口令；
3. 若要对外交付，请用 `install.sh`（不带 `--factory`）走干净安装，或先重新签发 PKI。

---

## 四、本次版本变更（V1.0.1）

**新增**

- 出厂模板机制：`--factory` 一键复刻模板机（含 PKI、账号、隧道、策略）
- `--version` 参数；页脚版权信息「起点火箭开发 · 2026年10月21日 · V1.0.1」
- OpenVPN 客户端：导入 `.ovpn`、导出 `.ovpn`、固定隧道 IP（CCD `ifconfig-push`）
- OpenVPN 服务端：路由推送设置（内网 / 全流量 / 出向隧道远端网段 / 自定义网段）
- 虚拟专网：在线客户端实时列表 + 踢下线 + 启用/停用 + 历史记录
- 防火墙：VPN 客户端网段出隧道的 SNAT 与转发放行

**修复**

- 全新安装时 PPP 钩子渲染参数不足导致安装中断（需 5 个参数，原只传 3 个）
- 出向隧道勾选「全流量」会抢走默认路由，导致拨入客户端无法上网 → 未勾选时自动加 `pull-filter ignore redirect-gateway`
- 拨入客户端访问出向隧道远端内网不通 → 补充隧道口的 masquerade
- OpenVPN 证书缺少 EKU 扩展导致客户端 `VERIFY KU ERROR` → 签发时补齐并自愈存量证书
- pptpd 配置变更不触发重载
- 模板网卡名/IP 与新机不一致时的自动适配

---

## 五、安装后检查

```bash
systemctl status routeweb dnsmasq nftables openvpn@server
journalctl -u routeweb -n 50 --no-pager
nft list ruleset | head -40
cat /etc/routeweb/config.json
```

浏览器访问 `http://<LAN地址>:8080/`。

卸载（保留 state.json 与备份）：

```bash
sudo ./install.sh --uninstall
```
