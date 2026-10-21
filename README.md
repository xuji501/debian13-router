# RouteWeb 网关安装包 V1.0.1

起点火箭开发 · 2026年10月21日

把一台干净的 Debian 13 变成「路由 + 防火墙 + DNS/DHCP + VPN + Web 管理」的一体机。

> 本版本以现网运行中的网关为模板，附带 `factory/` 出厂配置。  
> 用 `--factory` 安装可**完整复刻**模板机的 VPN 证书、账号、隧道与防火墙策略。  
> 模板含私钥与口令，**仅限内部分发**，详见 `RELEASE.md` 的安全提示。

## 三种发行形态

| 形态     | 获取方式                                  | 说明                                            |
| ------ | ------------------------------------- | --------------------------------------------- |
| 一键安装包  | `dist/routeweb-gateway-1.0.1.tar.gz`  | 解压后 `./install.sh`，支持向导 / `--factory` / 无人值守  |
| DEB 包  | `dist/routeweb-gateway_1.0.1_all.deb` | `dpkg -i` 安装，再执行 `routeweb-install --factory` |
| ISO 镜像 | 包内 `build_iso.sh`                     | 需在 Debian 13 宿主机构建，产出的 ISO 可直接装机              |

## 特性

| 能力         | 说明                                                        |
| ---------- | --------------------------------------------------------- |
| NAT 网关     | LAN ⇄ WAN 转发、masquerade、端口转发（DNAT）、静态路由持久化                |
| DNS / DHCP | dnsmasq，按网段自动生成地址池、网关、DNS 下发                              |
| 防火墙        | nftables 策略 + 端口放行 + 拒绝规则（带命中计数器）                         |
| 流量监视       | 按业务类型（Web/DNS/SSH/邮件/文件/远程/数据库/VPN/ICMP）分类统计 + 接口实时速率     |
| VPN 服务端    | PPTP / L2TP-IPsec / OpenVPN / IKEv2 / WireGuard，一键启停与账号管理 |
| VPN 客户端    | 网关拨入远端，显示隧道 IP / 速率 / 流量，可指定远端网段让内网访问对端                   |
| Web 管理     | 纯标准库实现，零第三方依赖；LAN 与 VPN 隧道地址均可登录                          |

## 前置条件

- Debian 13 (trixie) **最小安装**（netinst），x86_64
- 两张网卡（WAN 接上级/外网，LAN 接内网交换机）
- 可访问 Debian 软件源
- root 权限

> 不要用带 GNOME 桌面的完整版做宿主：桌面环境会拉起 NetworkManager，和 `ifupdown` 抢网卡。安装脚本检测到会自动停用 NetworkManager。

## 快速开始

```bash
tar xzf routeweb-gateway-1.0.1.tar.gz
cd routeweb-gateway-1.0.1
sudo ./install.sh
```

向导会依次询问：WAN 网卡与取址方式、LAN 网卡与地址、上游 DNS、Web 端口、管理密码。  
安装完成后重启，用内网终端访问 `http://<LAN地址>:8080/`。

## 出厂模板安装（复刻模板机）

```bash
sudo ./install.sh --factory
```

把 `factory/rootfs/` 下 54 个配置文件按原路径铺进系统：`state.json`（防火墙/VPN 账号/客户端/DHCP/路由推送）、`auth.json`（管理密码）、OpenVPN 全套（server.conf + PKI + CCD + 拨号端）、PPTP/L2TP/IPsec/WireGuard 配置，并按模板启用 `openvpn@server`、`openvpn-client@ROS` 等服务。

只改网卡和 IP、其余照搬：

```bash
sudo ./install.sh --factory --config gw.conf
```

**不会装坏**的保护：模板网卡名在新机不存在时自动回退到本机检测；LAN 网段不同时自动重算 DHCP 池；`config.json`、`interfaces`、sysctl、systemd 单元与主程序始终按本机生成。

## DEB 包安装

```bash
sudo dpkg -i routeweb-gateway_1.0.1_all.deb
sudo routeweb-install --factory
```

deb 只放程序与模板到 `/usr/share/routeweb` 与 `/opt/routeweb`，**不自动改网络**；配置由 `routeweb-install` 完成。卸载：`sudo apt remove routeweb-gateway`（`purge` 会一并清除配置）。

## ISO 镜像

Windows 无法构建（debootstrap / xorriso / grub 均为 Linux 工具）。在 Debian 13 机器上：

```bash
sudo ./build_iso.sh                 # 产出 ../dist/routeweb-gateway-1.0.1.iso
sudo ./build_iso.sh --no-factory    # 不含出厂模板的干净安装盘
```

ISO 启动后按提示确认，系统写入第一块硬盘，重启后再执行 `routeweb-install --factory` 即完成。

## 无人值守安装（批量部署）

```bash
cp config.sample gw.conf
vi gw.conf                 # 填网卡名、IP、密码
sudo ./install.sh --config gw.conf
```

配置文件逐行 `键 = 值`，`#` 开头为注释。未写的项走默认值。

## 只有一个网卡 / 试验环境

```bash
sudo ./install.sh --dry-run     # 只看会做什么，不改系统
```

## 参数

| 参数                | 作用                        |
| ----------------- | ------------------------- |
| `--factory`       | 套用出厂模板 `factory/`，复刻模板机配置 |
| `--config FILE`   | 从配置文件读取参数（无人值守，优先级高于模板）   |
| `--version`       | 显示版本信息                    |
| `--password PW`   | 直接指定 Web 管理密码             |
| `--apply-network` | 安装后立即重启网络（会断开 SSH）        |
| `--keep-nm`       | 保留 NetworkManager（默认会停用）  |
| `--no-apt`        | 跳过依赖安装                    |
| `--no-service`    | 跳过服务启用（只写文件）              |
| `--force`         | 非 Debian 13 也继续 / 覆盖已有密码  |
| `--dry-run`       | 演练模式                      |
| `--uninstall`     | 卸载（保留 state.json 与备份）     |

## 安装过程做了什么

1. 检查系统版本与程序文件
2. 按向导/配置文件确定网络参数
3. `apt-get install`：nftables、dnsmasq、pptpd、xl2tpd、pptp-linux、openvpn、strongswan-swanctl、wireguard-tools 等
4. 备份将被覆盖的配置到 `/var/backups/routeweb/<时间戳>/`
5. 写 `/etc/routeweb/config.json`（所有网络参数唯一来源）
6. 安装 `/opt/routeweb/{routeweb.py,apply_routes.py}`，初始化 `auth.json`（SHA256+salt）与 `state.json`
7. 写 `/etc/network/interfaces`、`/etc/sysctl.d/99-routeweb.conf`
8. 调用程序自身的生成器渲染 `/etc/nftables.conf`、`/etc/nftables-acct.conf`、`/etc/dnsmasq.conf`、PPP 上下线钩子
9. 安装并启用 `routeweb.service`、`routeweb-routes.service`、`nftables`、`dnsmasq`、`ssh`

## 目录与文件

```
/opt/routeweb/routeweb.py        # 主程序（Web + 配置生成）
/opt/routeweb/apply_routes.py    # 开机恢复静态路由
/opt/routeweb/state.json         # 运行状态（转发/规则/VPN/客户端/DHCP）
/opt/routeweb/auth.json          # 管理密码哈希
/etc/routeweb/config.json        # 安装参数（网卡/IP/端口/DNS）
/etc/routeweb/nets/<客户端名>    # VPN 客户端的远端网段
/etc/nftables.conf               # 过滤器规则（每次改动由程序重写）
/etc/nftables-acct.conf          # 流量统计表（独立，避免改规则清零）
/etc/dnsmasq.conf                # DNS/DHCP
/etc/ppp/ip-up.d/routeweb-tunnel # 拨号上线钩子（记录隧道 + 下发远端网段）
/usr/share/routeweb/factory/     # deb 安装后的出厂模板位置
```

发布相关：

```
installer/factory/rootfs/        # 出厂模板（与 / 同构，54 个文件）
installer/factory/FACTORY.json   # 模板元信息（来源主机、WAN 取址方式、程序 md5）
installer/factory/MANIFEST.txt   # 模板文件清单
installer/RELEASE.md             # 发布说明与安全提示
installer/CHANGELOG.md           # 变更记录
installer/build_iso.sh           # ISO 构建脚本（Debian 宿主机执行）
build_release.py                 # 一键生成 tar.gz + deb + 校验清单（全平台）
test_release.py                  # 发行产物离线校验
verify_release_live.py           # 网关真机验证
```

## 日常运维

```bash
systemctl status routeweb dnsmasq nftables
journalctl -u routeweb -n 50 --no-pager
nft list ruleset | head -40
cat /etc/routeweb/config.json          # 当前网络参数
cat /var/log/routeweb-ppp/<客户端>.log  # VPN 拨号日志
```

换 IP / 换网卡：改 `/etc/routeweb/config.json` 与 `/etc/network/interfaces`，然后 `reboot`。

## 卸载

```bash
sudo ./install.sh --uninstall
```

删除服务、`/opt/routeweb`、`/etc/routeweb`、PPP 钩子；防火墙与 dnsmasq 配置保留（如需还原，从备份目录复制）。
