#!/bin/bash

set -e

outfile="./xp.py"
cp ~/code/stuff/lin_pwn_skel.py ${outfile}
sed -i "s/sys.argv\[1\]/'$1'/" ${outfile}
sed -i "s/int(sys.argv\[2\])/$2/" ${outfile}
sed -i "s?os.path.realpath(\"./changeme\")?os.path.realpath(\"$3\")?" ${outfile}