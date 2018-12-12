import struct
import sys
import haclib


if len(sys.argv) != 2:
    print("usage: python %s [filename]\n" % (sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]    

signature = b"PK\x03\x04"

top = 0
index = 0
while True:
    top = haclib.search_bytes_next(filename, signature, top)
    write_filename = "localfile%03d.dat" % (index)
    if top == -1:
        break;
    print("*****************************")
    rf = open(filename, "r")
    rf.seek(top)
    wf = open(write_filename, "w")
    haclib.zip_extract_localfile(rf, wf)
    rf.close()
    wf.close()
    print("*****************************")
    
    top += len(signature)
    index += 1
