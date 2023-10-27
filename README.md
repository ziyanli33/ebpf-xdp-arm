# XDP
## Introduction
This repository illustrates how to run an IP statistics eBPF xDP program on an arm64 Ubuntu VM on Mac M-series laptops.

Inspired by [cilium ebpf example](https://github.com/cilium/ebpf/blob/main/examples/xdp/main.go)
## Preparation
1. Install [UTM](https://github.com/utmapp/UTM/releases/download/v4.4.4/UTM.dmg)
2. Download [Ubuntu 22.04 arm64](https://cdimage.ubuntu.com/jammy/daily-live/current/jammy-desktop-arm64.iso)
3. (Optional)Install homebrew clang `brew install llvm`
### Run UTM VM
1. Start Ubuntu 22.04 arm64 VM via UTM, share the repository directory
2. Mount the shared directory inside the VM `sudo mkdir /media/share && sudo mount -t virtiofs share /media/share`
3. (Optional)Cross compile `xdp.elf` if not using linux arm64
    ```
    /opt/homebrew/opt/llvm/bin/clang -I headers -O -target bpf-linux-eabi -c bpf/xdp.c -o bpf/xdp.elf
    ```
4. Cross compile user-space golang binary
    ```
    env GOOS=linux GOARCH=arm64 go build -o xdp-linux-arm64
    ```
5. Run the binary inside the VM
    ```
    cd /media/share/xdp/
    ./xdp-linux-arm64
    ```
