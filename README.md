# XDP-NAVT

NAVT(Network Address Vlan Translation) with XDP

VID:100, 192.168.0.1(inside) <=> VID:98, 10.10.0.1 (outside)  
VID:1500, 192.168.0.1(inside) <=> VID:98, 10.15.0.1 (outside)

## Build
In today's Linux, bpf_helper_defs.h is supposed to build.
If you hit this script accordingly, it will fetch the kernel code and build it.
Please use according to your kernel version.
There is no problem with the first execution.

```shell
./gen_bpf_helper.sh
```

dev packages install

```shell
sudo apt install clang llvm libelf-dev build-essential linux-headers-$(uname -r) linux-libc-dev libbpf-dev gcc-multilib clang-format
```

Let's build go & ebpf
```shell
make
```

## Run
```shell
./bin/xdp-navt

# use option
./bin/xdp-navt --device eth2
```

## Test
```shell
make test
```
