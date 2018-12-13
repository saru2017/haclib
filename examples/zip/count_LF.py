import struct
import sys
import haclib


if len(sys.argv) != 2:
    print("usage: python %s [filename]\n" % (sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]    

signature = b"PK\x03\x04"

file_count = 0
top = 0
while True:
    top = haclib.search_bytes_next(filename, signature, top)
    if top == -1:
        break;
    top += len(signature)
    file_count += 1

print(file_count)
