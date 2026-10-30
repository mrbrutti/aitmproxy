#!/aitm-boot/busybox-arm64 sh
# arm64 bootstrap: set up in-container x86_64 binfmt, then hand off to bWAPP's
# native amd64 startup (which now runs under qemu via binfmt).
BB=/aitm-boot/busybox-arm64
$BB mount -t binfmt_misc none /proc/sys/fs/binfmt_misc 2>/dev/null
if [ ! -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ]; then
  $BB printf '%s' ':qemu-x86_64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/aitm-boot/qemu-x86_64-static:OCF' > /proc/sys/fs/binfmt_misc/register
fi
echo "[aitm-boot] binfmt ready; starting bWAPP (amd64 via qemu)"
exec /bin/bash /run.sh
