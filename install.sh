#!/usr/bin/bash

VMHOST="arch@localhost"

BASE=linux-tlsm-
VER=6.18.7.arch1-1-x86_64.pkg.tar

PKGDIR="."
PKG1="$BASE$VER"
PKG2="tlsm-tools-git-0.0.1-1-x86_64.pkg.tar.zst"

pushd $PKGDIR || exit

scp -P 60022 $PKG1 $VMHOST:/tmp
ssh -p 60022 $VMHOST "cd /tmp && sudo pacman -U --noconfirm $PKG1" 

scp -P 60022 $PKG2 $VMHOST:/tmp
ssh -p 60022 $VMHOST "cd /tmp && sudo pacman -U --noconfirm $PKG2" 

popd || exit


ssh -p 60022 $VMHOST "sudo grub-mkconfig -o /boot/grub/grub.cfg"
ssh -p 60022 $VMHOST "sudo reboot"
