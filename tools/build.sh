#!/usr/bin/bash

rm -rf build
mkdir build
tar -czf ./build/tools-src.tar.gz src

cp PKGBUILD build/
pushd build || exit 
PKGDEST="../../" makepkg -sf
popd || exit
rm -rf build


