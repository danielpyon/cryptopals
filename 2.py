from base64 import b64encode

def htob64(string:bytes)->bytes:
    return b64encode(string)

def btoi(x:bytes)->int:
    return int.from_bytes(x, 'little')

def itob(x:int)->bytes:
    ret = bytearray()
    
    while x > 0:
        byte = x & 0xff
        ret.append(byte)
        x >>= 8

    ret.reverse()
    return ret

def xor(a:bytes, b:bytes)->bytes:
    assert len(a) == len(b)
    n = len(a)
    enc = bytearray()

    for i in range(n):
        curr_byte = a[i] ^ b[i]
        enc.append(curr_byte)
    return bytes(enc)


assert xor(itob(0x1c0111001f010100061a024b53535009181c), itob(0x686974207468652062756c6c277320657965)) == itob(0x746865206b696420646f6e277420706c6179)


