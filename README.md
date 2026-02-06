Introl attack
# File 
`linux.patch`: We add a new kernel module to implement rough single-step, interrupt injection and CSR modfication. These features are integrated in `single-step.c`
`kvmtool.patch`: We provide a dedicated vcpu_run interface for verification and modify kvmtool to call them.
`cvm_attack_poc`: The POC of the Introl attack.
`app`: POC executable program used to fast verification.

# Reproducing the Introl Attack
This section describes how to reproduce the Introl attack using the HyperTEE CVM implementation.

## 1. Clone the HyperTEE CVM Repository
```bash
git clone https://gitee.com/iie-cas/xs-cvm.git
cd xs-cvm
```

## 2. Apply the Patches
Apply the provided patches to both kvmtool and Linux components.

Apply kvmtool patch. 
```bash
cd kvmtool
patch -p1 < kvmtool.patch
cd ..
```

Apply Linux patch
```bash
patch -p1 < linux.patch
```
## 3. Add PoC Programs to the Guest Image
Edit the script `build-host.sh` to include the proof-of-concept (PoC) binaries in the guest filesystem.
Add the following commands to the script:

```bash
cp -f ./app/openssh_auth_test busybox-1.33.1/_install/apps
cp -f ./app/pam_auth_test     busybox-1.33.1/_install/apps
cp -f ./app/thread_test       busybox-1.33.1/_install/apps
```

## 4. Build and Run Host

Follow the official HyperTEE build and execution instructions provided in the project README:(Refer to the HyperTEE README for environment setup and dependency details.)

```bash
./build-tool.sh
./build-host.sh
./boot-host-os.sh
```

## 5. Run Guest
Run within the host.

```bash
#!/bin/sh
./apps/lkvm-static run -m 512 -c2 --console serial -p "root=/dev/ram console=ttyS0 earlycon=uart8250,mmio,0x3f8" -k ./apps/Image --debug --cvm-openssh
```


## 6. Run POC executable program in the Guest.
```bash
./openssh_auth_test any_password
```
