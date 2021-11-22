def circular_lshift(n, w):
    return ((w << n) | (w >> 32 - n)) & 0xffffffff

msg = "abc"

# preprocessing
ml = len(msg) * 8
msg = bytearray(msg, "utf-8")
msg += b"\x80"
if len(msg) != 56:
    msg.extend((56 - len(msg)) * b"\x00")
msg.extend(int.to_bytes(ml, 8, "big"))

# Initialize variables:
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0

chunks = [msg[i:i+64] for i in range(0, len(msg), 64)]
for chunk in chunks:
    w = [int.from_bytes(chunk[i:i+4], "big") for i in range(0, len(chunk), 4)]
    for i in range(16, 80):
        w.append(circular_lshift(1, w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]))
    # initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    # main loop
    for i in range(0, 80):
        if 0 <= i <= 19:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d) 
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = circular_lshift(5, a) + f + e + k + w[i] & 0xffffffff
        e = d
        d = c
        c = b << 30
        c = circular_lshift(30, b)
        b = a
        a = temp 
    
    h0 = h0 + a & 0xffffffff
    h1 = h1 + b & 0xffffffff
    h2 = h2 + c & 0xffffffff
    h3 = h3 + d & 0xffffffff
    h4 = h4 + e & 0xffffffff

hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
# int.to_bytes(hh, 20, "big")
# format(hh, "x")