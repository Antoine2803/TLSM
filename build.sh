#!/usr/bin/bash

echo "==== Building Linux-TLSM ===="

if [ ! -d "linux" ]; then
    echo -e "Downloading vanilla arch kernel pkg"
    git clone https://gitlab.archlinux.org/archlinux/packaging/packages/linux
    pushd linux || exit
    git checkout 6.18.9.arch1-2
    rm -rf .git
    popd || exit
fi

rm -f linux/tlsm.tar.gz

tar -czf linux/tlsm.tar.gz src --transform s/src/tlsm-src/
cp config linux/config
cp Kconfig.diff linux/Kconfig.diff
cp Makefile.diff linux/Makefile.diff

patch -N linux/PKGBUILD PKGBUILD.diff

pushd linux || exit
PKGEXT='.pkg.tar' PKGDEST=".." makepkg -cf
popd || exit

echo "==== Building TLSM Userland Tools ===="
pushd tools || exit
source build.sh
popd || exit
echo "==== DONE ===="