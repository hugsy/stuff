#!/usr/bin/env bash

set -e
set -x

NB_CORES="$(grep -c processor /proc/cpuinfo)"


install_python()
{
    ver=$1
    pushd .
    cd /opt
    curl -fsSL https://www.python.org/ftp/python/${ver}/Python-${ver}.tgz | sudo tar xfz -
    cd Python-${ver}
    sudo ./configure --enable-optimizations
    sudo make -j ${NB_CORES}
    sudo make -j ${NB_CORES} altinstall
    popd
}


migrate_packages()
{
    ver=$1
    tmp=$(tempfile)
    python -m pip freeze > ${tmp}
    /opt/Python-${ver}/python -m pip install --upgrade --user setuptools wheel
    /opt/Python-${ver}/python -m pip install --upgrade --user --no-color  -r ${tmp}
    rm -- ${tmp}
}


if [ $# -lt 1 ]
then
    echo "Missing desired Python version (example: 3.8.0)"
    exit 1
fi

install_python $1

migrate_packages $1

exit 0
