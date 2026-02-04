# TLSM

## VM
Deploy our test environement. Based on QEMU running arch-boxes images, with an overlayfs to speed up iteration.
Usage: `./vm.sh <base?> <reset>`
- base boots into the main image. This is required for initial setup after downloading the official arch-boxes image
- reset: reset the overlayfs (only needed if you broke the VM !)

## Build
Downloads the ArchLinux's default kernel and applies patches to inject TLSM, then builds arch packages.
`time ./build.sh > >(tee build.log) 2> >(tee build.err >&2)`

## Install
Install our kernels to a running VM.
`./install.sh`

