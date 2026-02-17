#!/usr/bin/bash

rm -rf build dist
echo -e "building static tlsmd with pyinstall using venv. Setup your venv if this fails !"

if [ ! -d "../venv/bin/activate" ]; then
    
    python -m venv ../venv
    source ../venv/bin/activate
    pip install -r requirements.txt 
else
    source ../venv/bin/activate
fi

pyinstaller --collect-all "six" -F src/tlsm-daemon.py

rm -rf build
mkdir build

tar -czf ./build/tools-src.tar.gz src dist

cp PKGBUILD build/
pushd build || exit 

PKGDEST="../../" makepkg -sf
popd || exit

rm -rf dist
rm -rf build