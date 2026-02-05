#!/usr/bin/bash

mkdir -p vm
pushd vm || exit 1

BASEFS="Arch-Linux-x86_64-basic.qcow2"
OVERLAYFS="overlay.qcow2"
FS=$OVERLAYFS

if [ ! -f $BASEFS ]; then
    echo -e "Downloading Arch QEMU Image"
    wget https://fastly.mirror.pkgbuild.com/images/v20260201.486653/Arch-Linux-x86_64-basic.qcow2

    echo -e "For all other scripts to work, you need to edit the base image."
    echo -e "remove arch account password: passwd -d arch"
    echo -e "enable EmptyPassword in /etc/ssh/sshd_config"
    echo -e "(Optional) localectl set-keymap"
    echo -e "Exiting."
    exit
fi

if [[ "$1" == "reset" ]]; then
    echo -e "RESETING OVERLAYFS"
    rm $OVERLAYFS
fi

if [ ! -f $OVERLAYFS ] 
then
    echo -e "Creating new overlayfs $OVERLAYFS"
    qemu-img create -o backing_file="$BASEFS",backing_fmt=qcow2 -f qcow2 "$OVERLAYFS"
else
    echo -e "Re-using existing overlayfs $OVERLAYFS"
fi

if [[ "$1" == "base" ]]; then
    echo -e "RUNNING BASE IMAGE."
    FS=$BASEFS
fi

qemu-system-x86_64 -smp 2 -enable-kvm -nic user,hostfwd=tcp::60022-:22 -m 1G "$FS"

popd || exit