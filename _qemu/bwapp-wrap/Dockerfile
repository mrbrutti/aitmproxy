FROM raesene/bwapp
COPY busybox-arm64 /aitm-boot/busybox-arm64
COPY qemu-x86_64-static /aitm-boot/qemu-x86_64-static
COPY boot.sh /aitm-boot/boot.sh
ENTRYPOINT ["/aitm-boot/busybox-arm64", "sh", "/aitm-boot/boot.sh"]
