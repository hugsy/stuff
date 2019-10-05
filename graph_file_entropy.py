#
# graph_file_entropy.py
#

import sys
import math
import numpy as np
import matplotlib.pyplot as plt

if len(sys.argv) != 2:
    print("Usage: file_entropy.py [path]filename")
    sys.exit()

# read the whole file into a byte array
data = bytearray(open(sys.argv[1], "rb").read())

# calculate the frequency of each byte value in the file
freqList = []
for b in range(256):
    ctr = 0
    for byte in data:
        if byte == b:
            ctr += 1
    freqList.append(float(ctr) / len(data))

# Shannon entropy
ent = 0.0
for freq in freqList:
    if freq > 0:
        ent = ent + freq * math.log(freq, 2)
ent = -ent


N = len(freqList)

ind = np.arange(N)  # the x locations for the groups
width = 1.00        # the width of the bars

fig = plt.figure(figsize=(11,5),dpi=100)
ax = fig.add_subplot(111)
rects1 = ax.bar(ind, freqList, width)
ax.set_autoscalex_on(False)
ax.set_xlim([0,255])

ax.set_ylabel('Frequency')
ax.set_xlabel('Byte')
ax.set_title('Frequency of Bytes 0 to 255\nFILENAME: ' + sys.argv[1])

plt.show()