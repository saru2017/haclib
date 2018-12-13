import haclib
import sys

if len(sys.argv) != 2:
    print("usage: python %s [filename]\n" % (sys.argv[0]))
    sys.exit(-1)

filename = sys.argv[1]    

haclib.zip_make_CDH(filename, 0)
