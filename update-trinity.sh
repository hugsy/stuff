#!/bin/bash
#
# Install/update Capstone/Keystone/Unicorn from GitHub with Python/Python3 bindings
# First time, run:
# $ sudo apt-get install git cmake gcc g++ pkg-config libglib2.0-dev
#

LOGFILE=/tmp/update-trinity.log
NB_CPU="$(grep -c processor /proc/cpuinfo)"

exec >${LOGFILE}
set -e

echo "[+] Log file is in '${LOGFILE}'" >&2
echo "[+] Starting compilation on ${NB_CPU} core(s)" >&2

pushd .

echo "[+] Installing keystone + bindings" >&2
pushd /tmp
git clone --quiet https://github.com/keystone-engine/keystone.git
mkdir -p keystone/build && cd keystone/build
sed -i "s/make -j8/make -j${NB_CPU}/g" ../make-share.sh
../make-share.sh
sudo make install
cd ../bindings/python
sudo make install install3
popd
echo "[+] Done" >&2

echo "[+] Installing capstone + bindings" >&2
pushd /tmp
git clone --quiet https://github.com/aquynh/capstone.git
cd capstone
./make.sh default -j${NB_CPU}
sudo ./make.sh install
cd ./bindings/python
sudo make install install3
popd
echo "[+] Done" >&2

echo "[+] Installing unicorn + bindings" >&2
pushd /tmp
git clone --quiet https://github.com/unicorn-engine/unicorn.git
cd unicorn
UNICORN_QEMU_FLAGS="--python=`which python2`" MAKE_JOBS=${NB_CPU} ./make.sh
sudo ./make.sh install
cd ./bindings/python
sudo make install install3
popd
echo "[+] Done" >&2

echo "[+] Cleanup" >&2
sudo rm -fr -- /tmp/{keystone,capstone,unicorn}
sudo ldconfig

popd
