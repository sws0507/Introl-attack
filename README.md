Introl

# Overview
This repository contains patches and proof-of-concept (PoC) code for the "Introl" attack research. The changes demonstrate mechanisms for single-stepping, interrupt injection, and CSR mediation in a RISC-V virtualization environment (HyperTEE / CVM).

# File summaries
- `introl/linux.patch`: Adds a kernel component that implements coarse single-step, interrupt injection and CSR modification hooks. Implementation details live in `single-step.c` and related kernel sources.

- `introl/kvmtool.patch`: Adds a dedicated `vcpu_run` interface and modifies `kvmtool` so the tool can call the new interface for verification and testing.

- `mediation/linux.patch`: VMM-side patch that replaces raw host writes to guest VS CSRs with typed exception-reflection requests while reusing Linux KVM virtual-instruction emulation.

- `mediation/opensbi.patch`: TSM-side patch that validates typed reflection requests, enforces the safe VS-CSR boundary, and commits only allowed guest-visible trap-state updates.

- `cvm_attack_poc`: Proof-of-concept code demonstrating the Introl attack techniques against the HyperTEE CVM.

- `app`: Small user-space test programs used to quickly exercise the PoCs (e.g., auth tests and a threaded test).

# Reproducing the Introl Attack (and Mediation)
This section describes how to reproduce the Introl attack using the HyperTEE CVM implementation.

## 1. Clone the HyperTEE CVM Repository
```bash
git clone https://gitee.com/iie-cas/xs-cvm.git
cd xs-cvm
```

## 2. Apply the Patches
Apply the provided patches to the kvmtool and Linux components in the HyperTEE CVM repository. The Introl patches are provided under the `introl/` directory of this repository.

Apply kvmtool patch:
```bash
patch -p1 < kvmtool.patch
```

Apply Linux patch (kernel tree root):
```bash
patch -p1 < linux.patch
```

If you want to test the mediation layer in addition, apply the patches from the `mediation/` directory.

## 3. Add PoC Programs to the Guest Image
Edit the script `build-host.sh` to include the proof-of-concept (PoC) binaries in the guest filesystem.
Add the following commands to the script:

```bash
cp -f ./app/openssh_auth_test busybox-1.33.1/_install/apps
cp -f ./app/pam_auth_test     busybox-1.33.1/_install/apps
cp -f ./app/thread_test       busybox-1.33.1/_install/apps
```

If you want to test the mediation layer in addition, edit the script `build-host.sh` to include the virtual-instruction test program:

```bash
cp -f ./app/rdcyc_example busybox-1.33.1/_install/apps
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


## 6. Run PoC executable program in the Guest
Run the included test binaries inside the guest to exercise the PoCs. Example:

```bash
./openssh_auth_test any_password
```

Notes and Requirements
- This repo is intended to be used with the HyperTEE CVM project. Follow that project's README for full build and environment setup.
- Kernel and kvmtool patches assume compatible Linux and kvmtool versions; adjust the patch offsets if your tree differs.
- Building the guest image requires the host build scripts referenced in the HyperTEE project.

Contact / Attribution
If you have questions about the PoC or patches, open an issue or contact the repository maintainers.

