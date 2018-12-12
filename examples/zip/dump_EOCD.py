import struct
import sys
import haclib


if len(sys.argv) != 2:
    print("usage: python %s [filename]\n" % (sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]    

signature = b"PK\x05\x06"

top = 0
while True:
    top = haclib.search_bytes_next(filename, signature, top)
    if top == -1:
        break;
    print("addr = 0x%x" % (top))
    print("*****************************")
    f = open(filename, "r")
    f.seek(top)
    haclib.zip_read_EOCD(f)
    f.close()
    print("*****************************")
    
    top += len(signature)
