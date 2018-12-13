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



def val2str(val):
    ret = b""
    items = p(val)
    for item in items:
        ret += b"\\x%02x" % (int(item))
    return ret;



### zip related functions
def zip_print_time(val):
    val = struct.unpack("<H", val)[0]
#    print("val = %d %x" % (val, val))

    ret = 0
    for i in range(5):
        ret = ret << 1
        if (0x8000 & val) != 0:
           ret = ret | 0x01 
        val = val << 1
    h = ret

    ret = 0
    for i in range(6):
        ret = ret << 1
        if (0x8000 & val) != 0:
           ret = ret | 0x01 
        val = val << 1
    m = ret

    ret = 0
    for i in range(5):
        ret = ret << 1
        if (0x8000 & val) != 0:
           ret = ret | 0x01 
        val = val << 1
    s = ret * 2
    print("%02d:%02d:%02d" % (h, m, s))

    

def zip_print_date(val):
    val = struct.unpack("<H", val)[0]
#    print("val = %d %x" % (val, val))

    ret = 0
    for i in range(7):
        ret = ret << 1
        if (0x8000 & val) != 0:
           ret = ret | 0x01 
        val = val << 1
    y = ret + 1980

    ret = 0
    for i in range(4):
        ret = ret << 1
        if (0x8000 & val) != 0:
           ret = ret | 0x01 
        val = val << 1
    m = ret

    ret = 0
    for i in range(5):
        ret = ret << 1
        if (0x8000 & val) != 0:
           ret = ret | 0x01 
        val = val << 1
    d = ret
    print("%02d/%02d/%02d" % (y, m, d))


    
def zip_read_localfile(f):
    readed_size = 0
    
    signature = f.buffer.read(4)
    readed_size += 4
    print("signature: " , end="")
    print(signature)

    version = f.buffer.read(2)
    readed_size += 2
    version = struct.unpack("<H", version)[0]
    print("version: " , end="")
    print(version)

    bitflag = f.buffer.read(2)
    readed_size += 2    
    print("bitflat: " , end="")
    print(bitflag)

    compress_method = f.buffer.read(2)
    readed_size += 2    
    print("compress_method: " , end="")
    print(compress_method)

    timebits = f.buffer.read(2)
    readed_size += 2    
    print("timebits: " , end="")
    zip_print_time(timebits)

    datebits = f.buffer.read(2)
    readed_size += 2
    print("datebits: " , end="")
    zip_print_date(datebits)

    crc32 = f.buffer.read(4)
    readed_size += 4
    crc32 = struct.unpack("<I", crc32)[0]
    print("crc32: " , end="")
    print("0x%08x" % (crc32))

    compsize = f.buffer.read(4)
    readed_size += 4
    compsize = struct.unpack("<I", compsize)[0]
    print("compsize: " , end="")
    print(compsize)

    size = f.buffer.read(4)
    readed_size += 4    
    size = struct.unpack("<I", size)[0]
    print("size: " , end="")
    print(size)

    namelen = f.buffer.read(2)
    readed_size += 2    
    namelen = struct.unpack("<H", namelen)[0]
    print("namelen: " , end="")
    print(namelen)

    extlen = f.buffer.read(2)
    readed_size += 2    
    extlen = struct.unpack("<H", extlen)[0]
    print("extlen: " , end="")
    print(extlen)

    file_name = f.buffer.read(namelen)
    readed_size += namelen    
    print("file_name: " , end="")
    print(file_name)

    ext = f.buffer.read(extlen)
    readed_size += extlen    
    print("ext: " , end="")
    print(ext)

    content = f.buffer.read(compsize)
    readed_size += compsize    
    print("content: " , end="")
    print(content)

    return readed_size



def zip_read_LFH(f):
    readed_size = 0
    
    signature = f.buffer.read(4)
    readed_size += 4
    print("signature: " , end="")
    print(signature)

    version = f.buffer.read(2)
    readed_size += 2
    version = struct.unpack("<H", version)[0]
    print("version: " , end="")
    print(version)

    bitflag = f.buffer.read(2)
    readed_size += 2    
    print("bitflat: " , end="")
    print(bitflag)

    compress_method = f.buffer.read(2)
    readed_size += 2    
    print("compress_method: " , end="")
    print(compress_method)

    timebits = f.buffer.read(2)
    readed_size += 2    
    print("timebits: " , end="")
    zip_print_time(timebits)

    datebits = f.buffer.read(2)
    readed_size += 2
    print("datebits: " , end="")
    zip_print_date(datebits)

    crc32 = f.buffer.read(4)
    readed_size += 4
    crc32 = struct.unpack("<I", crc32)[0]
    print("crc32: " , end="")
    print("0x%08x" % (crc32))

    compsize = f.buffer.read(4)
    readed_size += 4
    compsize = struct.unpack("<I", compsize)[0]
    print("compsize: " , end="")
    print(compsize)

    size = f.buffer.read(4)
    readed_size += 4    
    size = struct.unpack("<I", size)[0]
    print("size: " , end="")
    print(size)

    namelen = f.buffer.read(2)
    readed_size += 2    
    namelen = struct.unpack("<H", namelen)[0]
    print("namelen: " , end="")
    print(namelen)

    extlen = f.buffer.read(2)
    readed_size += 2    
    extlen = struct.unpack("<H", extlen)[0]
    print("extlen: " , end="")
    print(extlen)

    file_name = f.buffer.read(namelen)
    readed_size += namelen    
    print("file_name: " , end="")
    print(file_name)

    ext = f.buffer.read(extlen)
    readed_size += extlen    
    print("ext: " , end="")
    print(ext)

    return readed_size



def zip_read_CDH(f):
    readed_size = 0
    
    signature = f.buffer.read(4)
    readed_size += 4
    print("signature: " , end="")
    print(signature)

    version = f.buffer.read(2)
    readed_size += 2
    print("version made by: " , end="")
    print(version)

    version = f.buffer.read(2)
    readed_size += 2
    version = struct.unpack("<H", version)[0]
    print("version needed to extract: " , end="")
    print(version)
    
    bitflag = f.buffer.read(2)
    readed_size += 2    
    print("bitflat: " , end="")
    print(bitflag)

    compress_method = f.buffer.read(2)
    readed_size += 2    
    print("compress_method: " , end="")
    print(compress_method)

    timebits = f.buffer.read(2)
    readed_size += 2    
    print("timebits: " , end="")
    zip_print_time(timebits)

    datebits = f.buffer.read(2)
    readed_size += 2
    print("datebits: " , end="")
    zip_print_date(datebits)

    crc32 = f.buffer.read(4)
    readed_size += 4
    crc32 = struct.unpack("<I", crc32)[0]
    print("crc32: " , end="")
    print("0x%08x" % (crc32))

    compsize = f.buffer.read(4)
    readed_size += 4
    compsize = struct.unpack("<I", compsize)[0]
    print("compsize: " , end="")
    print(compsize)

    size = f.buffer.read(4)
    readed_size += 4    
    size = struct.unpack("<I", size)[0]
    print("size: " , end="")
    print(size)

    namelen = f.buffer.read(2)
    readed_size += 2    
    namelen = struct.unpack("<H", namelen)[0]
    print("namelen: " , end="")
    print(namelen)

    extlen = f.buffer.read(2)
    readed_size += 2    
    extlen = struct.unpack("<H", extlen)[0]
    print("extlen: " , end="")
    print(extlen)

    commentlen = f.buffer.read(2)
    readed_size += 2    
    commentlen = struct.unpack("<H", commentlen)[0]
    print("commentlen: " , end="")
    print(commentlen)

    disk_number_start = f.buffer.read(2)
    readed_size += 2    
    disk_number_start = struct.unpack("<H", disk_number_start)[0]
    print("disk_number_start: " , end="")
    print(disk_number_start)

    internal_attr = f.buffer.read(2)
    readed_size += 2    
    print("internal_attr: " , end="")
    print(internal_attr)

    external_attr = f.buffer.read(4)
    readed_size += 4
    print("external_attr: " , end="")
    print(external_attr)

    rel_offset = f.buffer.read(4)
    readed_size += 4
    rel_offset = struct.unpack("<I", rel_offset)[0]
    print("rel_offset: " , end="")
    print(rel_offset)
    
    file_name = f.buffer.read(namelen)
    readed_size += namelen    
    print("file_name: " , end="")
    print(file_name)

    ext = f.buffer.read(extlen)
    readed_size += extlen    
    print("ext: " , end="")
    print(ext)

    comment = f.buffer.read(commentlen)
    readed_size += commentlen
    print("commet: " , end="")
    print(comment)
    
    return readed_size



def zip_read_EOCD(f):
    readed_size = 0
    
    signature = f.buffer.read(4)
    readed_size += 4
    print("signature: " , end="")
    print(signature)

    disk_index = f.buffer.read(2)
    readed_size += 2
    print("disk index: " , end="")
    disk_index = struct.unpack("<H", disk_index)[0]
    print(disk_index)

    start_disk_index = f.buffer.read(2)
    readed_size += 2
    start_disk_index = struct.unpack("<H", start_disk_index)[0]
    print("start_disk_index: " , end="")
    print(start_disk_index)

    num_of_entries_on_disk = f.buffer.read(2)
    readed_size += 2
    num_of_entries_on_disk = struct.unpack("<H", num_of_entries_on_disk)[0]
    print("num_of_entries_on_disk: " , end="")
    print(num_of_entries_on_disk)
    
    total_num_of_entries = f.buffer.read(2)
    readed_size += 2
    total_num_of_entries = struct.unpack("<H", total_num_of_entries)[0]
    print("total_num_of_entries: " , end="")
    print(total_num_of_entries)

    size = f.buffer.read(4)
    readed_size += 4
    size = struct.unpack("<I", size)[0]
    print("size: " , end="")
    print(size)

    offset = f.buffer.read(4)
    readed_size += 4
    offset = struct.unpack("<I", offset)[0]
    print("offset: " , end="")
    print(offset)    

    commentlen = f.buffer.read(2)
    readed_size += 2    
    commentlen = struct.unpack("<H", commentlen)[0]
    print("commentlen: " , end="")
    print(commentlen)

    comment = f.buffer.read(commentlen)
    readed_size += commentlen
    print("commet: " , end="")
    print(comment)
    
    return readed_size



def search_bytes_next(filename, b, start):
    f = open(filename, "r")
    f.seek(start)
    top = start
    rb = b""
    for i in range(len(b)):
        rb += f.buffer.read(1)

    while True:
        if rb == b:
            f.close()
            return top
        top += 1
        tmp_b = f.buffer.read(1)
        if tmp_b == b"":
            return -1
        rb += tmp_b
        rb = rb[1:]



def zip_extract_LF(rf, wf):
    readed_size = 0
    
    signature = rf.buffer.read(4)
    readed_size += 4
    wf.buffer.write(signature)
    print("signature: " , end="")
    print(signature)

    version = rf.buffer.read(2)
    readed_size += 2
    wf.buffer.write(version)

    bitflag = rf.buffer.read(2)
    readed_size += 2
    wf.buffer.write(bitflag)

    compress_method = rf.buffer.read(2)
    readed_size += 2
    wf.buffer.write(compress_method)

    timebits = rf.buffer.read(2)
    readed_size += 2    
    wf.buffer.write(timebits)

    datebits = rf.buffer.read(2)
    readed_size += 2
    wf.buffer.write(datebits)

    crc32 = rf.buffer.read(4)
    readed_size += 4
    wf.buffer.write(crc32)

    compsize = rf.buffer.read(4)
    readed_size += 4
    wf.buffer.write(compsize)
    compsize = struct.unpack("<I", compsize)[0]
    print("compsize: " , end="")
    print(compsize)

    size = rf.buffer.read(4)
    readed_size += 4
    wf.buffer.write(size)

    namelen = rf.buffer.read(2)
    readed_size += 2    
    wf.buffer.write(namelen)
    namelen = struct.unpack("<H", namelen)[0]
    print("namelen: " , end="")
    print(namelen)

    extlen = rf.buffer.read(2)
    readed_size += 2    
    wf.buffer.write(extlen)
    extlen = struct.unpack("<H", extlen)[0]
    print("extlen: " , end="")
    print(extlen)

    file_name = rf.buffer.read(namelen)
    readed_size += namelen    
    wf.buffer.write(file_name)
    print("file_name: " , end="")
    print(file_name)

    ext = rf.buffer.read(extlen)
    readed_size += extlen
    wf.buffer.write(ext)

    content = rf.buffer.read(compsize)
    readed_size += compsize    
    wf.buffer.write(content)

    return readed_size
        


def zip_make_CDH(filename, offset):
    rf = open(filename, "r")
    wf = open(filename + ".cdh", "w")

    #signature
    wf.buffer.write(b"PK\x01\x02")
    signature = rf.buffer.read(4)

    #version x 2
    version = rf.buffer.read(2) #minimum
    wf.buffer.write(version)
    wf.buffer.write(version)

    bitflag = rf.buffer.read(2)
    wf.buffer.write(bitflag)

    compress_method = rf.buffer.read(2)
    wf.buffer.write(compress_method)

    timebits = rf.buffer.read(2)
    wf.buffer.write(timebits)

    datebits = rf.buffer.read(2)
    wf.buffer.write(datebits)

    crc32 = rf.buffer.read(4)
    wf.buffer.write(crc32)
    
    compsize = rf.buffer.read(4)
    wf.buffer.write(compsize)
    compsize = struct.unpack("<I", compsize)[0]

    size = rf.buffer.read(4)
    wf.buffer.write(size)

    namelen = rf.buffer.read(2)
    wf.buffer.write(namelen)
    namelen = struct.unpack("<H", namelen)[0]

    extlen = rf.buffer.read(2)
    extlen = b"\x00\x00"
    wf.buffer.write(extlen)

    commentlen = b"\x00\x00"
    wf.buffer.write(commentlen)

    disk_number_start = b"\x00\x00"
    wf.buffer.write(disk_number_start)
    
    internal_attr = b"\x00\x00"
    wf.buffer.write(internal_attr)

#    external_attr = b'\x00\x00\xa4\x81'
    external_attr = b'\x00\x00\x00\x00'
    wf.buffer.write(external_attr)

    rel_offset = struct.pack("<I", offset)
    wf.buffer.write(rel_offset)
    
    file_name = rf.buffer.read(namelen)
    wf.buffer.write(file_name)

    rf.close()
    wf.close()
    
    return filename + ".cdh"



def zip_make_EOCD(num_entries, size, offset, commentlen=0):
    wf = open("eocd.eocd", "w")

    #signature
    wf.buffer.write(b"PK\x05\x06")

    disk_index = b"\x00\x00"
    wf.buffer.write(disk_index)

    start_disk_index = b"\x00\x00"
    wf.buffer.write(start_disk_index)

    num_entries = struct.pack("<H", num_entries)
    wf.buffer.write(num_entries)
    wf.buffer.write(num_entries)

    size = struct.pack("<I", size)
    wf.buffer.write(size)

    offset = struct.pack("<I", offset)
    wf.buffer.write(offset)

    commentlen = struct.pack("H", commentlen)
    wf.buffer.write(commentlen)

    wf.close()
    
    return "eocd.eocd"

