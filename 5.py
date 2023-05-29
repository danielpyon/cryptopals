from base64 import b64encode

def htob64(string:bytes)->bytes:
    return b64encode(string)

def btoi(x:bytes)->int:
    return int.from_bytes(x, 'big')

def itob(x:int)->bytes:
    if x == 0:
        return b'\x00'

    ret = bytearray()
    
    while x > 0:
        byte = x & 0xff
        ret.append(byte)
        x >>= 8

    ret.reverse()
    return bytes(ret)

def btos(x:bytes)->str:
    return x.decode('ascii')

# bytes to alphanumeric string
def btoans(x:bytes)->str:
    s = ''
    for byte in x:
        if (ord('A') <= byte <= ord('Z')) or (ord('0') <= byte <= ord('9')) or (ord('a') <= byte <= ord('z')):
            s += chr(byte)
        else:
            raise Exception('Non-alphabetic characters in bytes')
    return s

def xor(a:bytes, b:bytes)->bytes:
    assert len(a) == len(b)
    n = len(a)
    enc = bytearray()

    for i in range(n):
        curr_byte = a[i] ^ b[i]
        enc.append(curr_byte)
    return bytes(enc)

def repeating_key_xor(x:bytes, key:bytes)->bytes:
    enc = bytearray()

    for i in range(len(x)):
        enc.append(x[i] ^ key[i % len(key)])

    return bytes(enc)

if __name__ == '__main__':
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode('ascii')
    ciphertext = repeating_key_xor(plaintext, b'ICE')

    assert btoi(ciphertext) == 0x0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
