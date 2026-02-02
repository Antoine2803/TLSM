#!/usr/bin/bash

VMHOST="arch@localhost"

BASE=linux-tlsm-
VER=6.18.7.arch1-1-x86_64.pkg.tar.zst

PKGDIR="./linux"
PKG1="$BASE$VER"
PKG2="${BASE}headers-$VER"

pushd $PKGDIR || exit
scp -P 60022 $PKG1 $VMHOST:/tmp
scp -P 60022 $PKG2 $VMHOST:/tmp
popd || exit
ssh -p 60022 $VMHOST "cd /tmp && sudo pacman -U --noconfirm $PKG1 $PKG2"
ssh -p 60022 $VMHOST "sudo grub-mkconfig -o /boot/grub/grub.cfg"
ssh -p 60022 $VMHOST "sudo reboot"
