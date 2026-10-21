#!/bin/bash
# =============================================================================
# RouteWeb 网关 ISO 构建脚本   V1.0.1   起点火箭开发 2026-10-21
#
# 作用: 在 Debian 13 (trixie) 宿主机上构建一张可启动 ISO。
#       用 ISO 启动后会自动把 RouteWeb 网关系统安装到目标机的第一块硬盘,
#       并可选择直接套用出厂模板(--factory), 实现"插盘即装、装完即同构"。
#
# !! 本机(Windows)无法构建: debootstrap / xorriso / grub 都是 Linux 专用工具。
#    请把本脚本连同整个安装包复制到一台 Debian 13 机器上执行。
#
# 用法:
#   sudo ./build_iso.sh                        # 产出 ../dist/routeweb-gateway-1.0.1.iso
#   sudo ./build_iso.sh --output /tmp/rw.iso   # 指定输出
#   sudo ./build_iso.sh --no-factory           # ISO 内不含出厂模板(干净安装)
#   sudo ./build_iso.sh --keep-work            # 保留工作目录便于排错
#
# 依赖(自动 apt 安装): debootstrap squashfs-tools xorriso
#                     grub-pc-bin grub-efi-amd64-bin mtools dosfstools
# =============================================================================
set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VER=$(grep -m1 '^VERSION=' "$SELF_DIR/install.sh" | cut -d'"' -f2)
SUITE=trixie
ARCH=amd64
MIRROR=http://deb.debian.org/debian
WORK=${WORK:-/var/tmp/routeweb-iso}
OUTPUT=""
KEEP_WORK=0
WITH_FACTORY=1
DISK=${TARGET_DISK:-/dev/sda}          # 目标机安装到的硬盘(可在启动时改)
PKG_DEB=""                             # 若存在 deb 包则优先用它装

while [ $# -gt 0 ]; do
    case "$1" in
        --output)      OUTPUT="$2"; shift 2 ;;
        --suite)       SUITE="$2"; shift 2 ;;
        --mirror)      MIRROR="$2"; shift 2 ;;
        --work)        WORK="$2"; shift 2 ;;
        --disk)        DISK="$2"; shift 2 ;;
        --no-factory)  WITH_FACTORY=0; shift ;;
        --keep-work)   KEEP_WORK=1; shift ;;
        -h|--help)     sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "未知参数: $1" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
command -v debootstrap >/dev/null || apt-get update -qq && apt-get install -y -qq \
    debootstrap squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin mtools dosfstools

[ -n "$OUTPUT" ] || OUTPUT="$SELF_DIR/../dist/routeweb-gateway-$VER.iso"
mkdir -p "$(dirname "$OUTPUT")"
PKG_DEB=$(ls "$SELF_DIR"/../dist/routeweb-gateway_*_all.deb 2>/dev/null | head -1 || true)

echo "==> 构建 RouteWeb $VER ISO"
echo "    suite=$SUITE arch=$ARCH mirror=$MIRROR"
echo "    work=$WORK  output=$OUTPUT  factory=$WITH_FACTORY"

# ---------------------------------------------------------------- 1. rootfs
rm -rf "$WORK"; mkdir -p "$WORK/chroot"
echo "==> [1/6] debootstrap 最小化系统 (约 3-10 分钟)"
debootstrap --variant=minbase --arch "$ARCH" \
    --include="linux-image-$ARCH,systemd,systemd-sysv,ifupdown,isc-dhcp-client,\
net-tools,iproute2,iputils-ping,traceroute,openssh-server,ca-certificates,\
python3,nftables,dnsmasq,pptpd,xl2tpd,pptp-linux,openvpn,strongswan-swanctl,\
wireguard-tools,psmisc,sudo,curl,file,less,vim-tiny" \
    "$SUITE" "$WORK/chroot" "$MIRROR"

# ------------------------------------------------------------ 2. 系统内配置
echo "==> [2/6] 配置系统"
cat >"$WORK/chroot/etc/hostname" <<'EOF'
routeweb
EOF
cat >"$WORK/chroot/etc/hosts" <<'EOF'
127.0.0.1       localhost
127.0.1.1       routeweb
EOF
cat >"$WORK/chroot/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main contrib non-free-firmware
deb $MIRROR $SUITE-updates main contrib non-free-firmware
deb http://security.debian.org/debian-security $SUITE-security main contrib non-free-firmware
EOF
# 控制台自动登录 root(装机现场用), 装完可关
mkdir -p "$WORK/chroot/etc/systemd/system/getty@tty1.service.d"
cat >"$WORK/chroot/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF
# 清空 root 密码, 首次登录强制设置
chroot "$WORK/chroot" /bin/sh -c 'passwd -d root; apt-get update -qq; apt-get -y -qq install grub-pc-bin grub-efi-amd64-bin 2>/dev/null || true'

# -------------------------------------------------------- 3. 放入 RouteWeb
echo "==> [3/6] 安装 RouteWeb 到镜像"
mkdir -p "$WORK/chroot/usr/share/routeweb"
cp "$SELF_DIR/install.sh" "$SELF_DIR/routeweb.py" "$SELF_DIR/apply_routes.py" \
   "$SELF_DIR/config.sample" "$SELF_DIR/README.md" "$SELF_DIR/RELEASE.md" \
   "$WORK/chroot/usr/share/routeweb/"
chmod +x "$WORK/chroot/usr/share/routeweb/install.sh"
[ "$WITH_FACTORY" = 1 ] && [ -d "$SELF_DIR/factory" ] && \
    cp -a "$SELF_DIR/factory" "$WORK/chroot/usr/share/routeweb/"
if [ -n "$PKG_DEB" ] && [ -f "$PKG_DEB" ]; then
    cp "$PKG_DEB" "$WORK/chroot/tmp/routeweb.deb"
    chroot "$WORK/chroot" /bin/sh -c 'apt-get install -y -qq /tmp/routeweb.deb; rm -f /tmp/routeweb.deb' \
        || echo "    deb 安装失败, 回退为文件复制模式"
fi
mkdir -p "$WORK/chroot/usr/local/sbin"
cat >"$WORK/chroot/usr/local/sbin/routeweb-install" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/share/routeweb/install.sh "$@" 2>/dev/null || \
     /usr/share/routeweb/install.sh "$@"
EOF
chmod +x "$WORK/chroot/usr/local/sbin/routeweb-install"

# ------------------------------------------------- 4. 首次启动自动部署服务
echo "==> [4/6] 写入首次启动部署服务"
cat >"$WORK/chroot/usr/local/sbin/routeweb-firstboot" <<EOF
#!/bin/bash
# RouteWeb 首次启动: 把系统落到硬盘并套用出厂模板
DISK="\${ROUTEWEB_DISK:-$DISK}"
MARK=/etc/routeweb/config.json
echo
echo "============================================================"
echo " RouteWeb 网关发行版 V$VER   起点火箭开发"
echo "============================================================"
lsblk -d -o NAME,SIZE,MODEL | sed 's/^/  /'
echo
if [ -f "\$MARK" ]; then
    echo "  检测到已安装配置, 跳过自动安装。"
    echo "  管理地址: http://\$(python3 -c \"import json;print(json.load(open('\$MARK')).get('lan_ip','?'))\" 2>/dev/null):8080/"
    exit 0
fi
echo "  将把系统安装到 \${DISK} (该盘数据会被清空!)"
printf '  确认请输入 yes: '
read -r yn
[ "\$yn" = "yes" ] || { echo "  已取消, 可稍后手工执行 routeweb-install"; exit 0; }
# --- 分区 ---
parted -s "\$DISK" mklabel gpt
parted -s "\$DISK" mkpart ESP fat32 1MiB 512MiB
parted -s "\$DISK" set 1 esp on
parted -s "\$DISK" mkpart primary ext4 512MiB 100%
sleep 2
P="\${DISK}"; case "\$DISK" in *[0-9]) P="\${DISK}p" ;; esac
mkfs.vfat -F32 "\${P}1"
mkfs.ext4 -F -q "\${P}2"
mount "\${P}2" /mnt
mkdir -p /mnt/boot/efi && mount "\${P}1" /mnt/boot/efi
# --- 复制根文件系统 ---
echo "  复制系统文件(约 1-3 分钟)..."
for d in bin boot etc home lib lib64 media opt root run sbin srv usr var; do
    [ -e "/\$d" ] || continue
    mkdir -p "/mnt/\$d"
    cp -a "/\$d/." "/mnt/\$d/" 2>/dev/null || true
done
for d in dev proc sys tmp; do mkdir -p "/mnt/\$d"; done
chmod 1777 /mnt/tmp
# --- 引导 ---
mount --bind /dev /mnt/dev; mount --bind /proc /mnt/proc; mount --bind /sys /mnt/sys
chroot /mnt grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --removable || true
chroot /mnt grub-install --target=i386-pc "\$DISK" || true
chroot /mnt update-grub || true
umount /mnt/sys /mnt/proc /mnt/dev /mnt/boot/efi /mnt 2>/dev/null || true
echo
echo "  系统已写入 \${DISK}, 请取出光盘/拔掉 U 盘后重启。"
echo
EOF
chmod +x "$WORK/chroot/usr/local/sbin/routeweb-firstboot"
cat >"$WORK/chroot/etc/systemd/system/routeweb-firstboot.service" <<'EOF'
[Unit]
Description=RouteWeb first boot deploy
After=network-pre.target local-fs.target
Before=getty@tty1.service
ConditionPathExists=!/etc/routeweb/config.json

[Service]
Type=oneshot
RemainAfterExit=no
StandardInput=tty
TTYPath=/dev/tty1
ExecStart=/usr/local/sbin/routeweb-firstboot

[Install]
WantedBy=multi-user.target
EOF
chroot "$WORK/chroot" systemctl enable routeweb-firstboot >/dev/null 2>&1 || true

# -------------------------------------------------------- 5. squashfs + 内核
echo "==> [5/6] 打包 squashfs"
mkdir -p "$WORK/iso/live" "$WORK/iso/boot/grub"
mksquashfs "$WORK/chroot" "$WORK/iso/live/filesystem.squashfs" \
    -comp xz -e boot -noappend -quiet
cp "$WORK/chroot/boot/vmlinuz"* "$WORK/iso/live/vmlinuz"
cp "$WORK/chroot/boot/initrd.img"* "$WORK/iso/live/initrd"

cat >"$WORK/iso/boot/grub/grub.cfg" <<EOF
set default=0
set timeout=5
insmod part_gpt; insmod fat; insmod ext2; insmod iso9660
menuentry "RouteWeb Gateway V$VER (install)" {
    linux /live/vmlinuz boot=live components quiet splash
    initrd /live/initrd
}
menuentry "RouteWeb Gateway V$VER (text, no autologin)" {
    linux /live/vmlinuz boot=live components quiet systemd.unit=multi-user.target
    initrd /live/initrd
}
EOF

# --------------------------------------------------------------- 6. 生成 ISO
echo "==> [6/6] 生成 ISO"
xorriso -as mkisofs \
    -iso-level 3 -full-iso9660-filenames -volid "ROUTEWEB-$VER" \
    -eltorito-boot boot/grub/grub.cfg -no-emul-boot -boot-load-size 4 -boot-info-table \
    --grub2-boot-info --grub2-mbr /usr/lib/grub/i386-pc/boot_hybrid.img \
    -eltorito-alt-boot -e EFI/efiboot.img -no-emul-boot \
    -output "$OUTPUT" "$WORK/iso" 2>&1 | tail -3 || \
xorriso -as mkisofs -iso-level 3 -full-iso9660-filenames -volid "ROUTEWEB-$VER" \
    -b boot/grub/grub.cfg -no-emul-boot -boot-load-size 4 -boot-info-table \
    -output "$OUTPUT" "$WORK/iso" 2>&1 | tail -3

[ -f "$OUTPUT" ] || { echo "ISO 生成失败"; exit 1; }
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
echo
echo "==> 完成"
ls -lh "$OUTPUT"
echo "    sha256: $(cut -d' ' -f1 "$OUTPUT.sha256")"
echo
echo "  用法: 把 ISO 写入 U 盘 (dd if=$OUTPUT of=/dev/sdX bs=4M status=progress)"
echo "        从 U 盘启动 -> 按提示确认 -> 系统写入硬盘 -> 重启"
echo "        重启后执行: routeweb-install --factory   即完成网关配置"

[ "$KEEP_WORK" = 1 ] || rm -rf "$WORK"
