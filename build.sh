#!/usr/bin/bash


if [ ! -d "linux" ]; then
    echo -e "Downloading vanilla arch kernel pkg"
    git clone https://gitlab.archlinux.org/archlinux/packaging/packages/linux
fi

rm -f linux/tlsm.tar.gz
rm -rf linux/src

tar -czf linux/tlsm.tar.gz src --transform s/src/tlsm-src/
cp config linux/config
cp Kconfig.diff linux/Kconfig.diff
cp Makefile.diff linux/Makefile.diff

patch -N linux/PKGBUILD PKGBUILD.diff

pushd linux || exit
makepkg -sf
popd || exit