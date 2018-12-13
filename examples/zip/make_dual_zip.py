import haclib
import sys
import os.path

if len(sys.argv) != 3:
    print("usage: python %s [filename1] [filename2]" % (sys.argv[0]))
    sys.exit(-1)

filename1 = sys.argv[1]
filename2 = sys.argv[2]

file1_size = os.path.getsize(filename1)
file2_size = os.path.getsize(filename2)

num_entries = 2
offset = 0
cd_size = 0
cdhlen = 54

cdhfilename1 = haclib.zip_make_CDH(filename1, 0)
offset = file1_size + cdhlen + 22
cdhfilename2 = haclib.zip_make_CDH(filename2, offset)

commentlen = file2_size + cdhlen + 22
haclib.zip_make_EOCD(1, cdhlen, file1_size, commentlen)

wf = open(filename1 + ".zip", "w")

rf = open(filename1)
buf = rf.buffer.read(1024)
while buf != b"":
    wf.buffer.write(buf)
    buf = rf.buffer.read(1024)
rf.close

filename = filename1 + ".cdh"
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

offset = file1_size + file2_size + cdhlen + 22
haclib.zip_make_EOCD(1, cdhlen, offset)

rf = open(filename2)
buf = rf.buffer.read(1024)
while buf != b"":
    wf.buffer.write(buf)
    buf = rf.buffer.read(1024)
rf.close

filename = filename2 + ".cdh"
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
