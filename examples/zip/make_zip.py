import haclib
import sys
import os.path

if len(sys.argv) == 1:
    print("usage: python %s [filename1] [filename2] ...\n" % (sys.argv[0]))
    sys.exit(-1)


num_entries = len(sys.argv) - 1
offset = 0
cd_size = 0
for i in range(num_entries):
    filename = sys.argv[i + 1]

    cdhfilename = haclib.zip_make_CDH(filename, offset)
    offset += os.path.getsize(filename)  #LDのfile size
    cd_size += os.path.getsize(cdhfilename) #CDのfile size

haclib.zip_make_EOCD(num_entries, cd_size, offset)

wf = open(filename + ".zip", "w")

for i in range(num_entries):
    filename = sys.argv[i + 1]
    rf = open(filename)
    buf = rf.buffer.read(1024)
    while buf != b"":
        wf.buffer.write(buf)
        buf = rf.buffer.read(1024)
    rf.close


    
for i in range(num_entries):
    filename = sys.argv[i + 1] + ".cdh"
    rf = open(filename)
    buf = rf.buffer.read(1024)

    while buf != b"":
        wf.buffer.write(buf)
        buf = rf.buffer.read(1024)
    rf.close
    
rf = open("eocd.eocd")

buf = rf.buffer.read(1024)
while buf != b"":
    wf.buffer.write(buf)
    buf = rf.buffer.read(1024)
rf.close

wf.close()
