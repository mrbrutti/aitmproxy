# amd64 bWAPP on Apple-Silicon rootless nerdctl/Lima

`raesene/bwapp` is amd64-only; this host runs rootless nerdctl in a Lima VM where
each container gets its own empty per-userns `binfmt_misc`, so host/VM-level qemu
registration never reaches containers. The fix is a wrapper image that registers
qemu **inside itself** at boot, then execs bWAPP's amd64 startup.

`Dockerfile` + `boot.sh` are the durable parts. The three binaries they need are
reproducible and git-ignored:

```sh
# static arm64 bootstrap shell (static-pie; the glibc busybox is dynamic and won't exec)
cid=$(docker create --platform linux/arm64 busybox:musl sh); docker export "$cid" | tar -xO 'bin/[' > busybox-arm64; docker rm "$cid"

# static arm64 qemu-x86_64 emulator (Lima mounts $HOME read-only, so capture via stdout)
docker run --rm --platform linux/arm64 debian:bookworm sh -c 'apt-get update -qq && apt-get install -y -qq qemu-user-static && cat /usr/bin/qemu-x86_64-static' > qemu-x86_64-static

chmod +x busybox-arm64 qemu-x86_64-static
cp busybox-arm64 qemu-x86_64-static bwapp-wrap/

# build + run (privileged needed for the in-container binfmt mount)
docker build --platform linux/amd64 -t bwapp-arm:latest bwapp-wrap
docker run -d --name bwapp --privileged --platform linux/amd64 -p 127.0.0.1:8088:80 bwapp-arm:latest
```
