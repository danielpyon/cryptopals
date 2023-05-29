from base64 import b64encode

def htob64(string:bytes)->bytes:
    return b64encode(string)

def btoi(x:bytes)->int:
    return int.from_bytes(x, 'little')

def itob(x:int)->bytes:
    if x == 0:
        return b'\x00'

    ret = bytearray()
    
    while x > 0:
        byte = x & 0xff
        ret.append(byte)
        x >>= 8

    ret.reverse()
    return ret

def btos(x:bytes)->str:
    return x.decode()

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

'''
Everything below is specific to problem 3
'''

ENGLISH_FREQS = {
    'T' : 9.10/100,
    'E' : 12.0/100,
    'A' : 8.12/100,
    'O' : 7.68/100,
    'I' : 7.31/100,
    'N' : 6.95/100,
    'S' : 6.28/100,
    'R' : 6.02/100,
    'H' : 5.92/100,
    'D' : 4.32/100,
    'L' : 3.98/100,
    'U' : 2.88/100,
    'C' : 2.71/100,
    'M' : 2.61/100,
    'F' : 2.30/100,
    'Y' : 2.11/100,
    'W' : 2.09/100,
    'G' : 2.03/100,
    'P' : 1.82/100,
    'B' : 1.49/100,
    'V' : 1.11/100,
    'K' : 0.69/100,
    'X' : 0.17/100,
    'Q' : 0.11/100,
    'J' : 0.10/100,
    'Z' : 0.07/100
}

def counts(x:str)->dict:
    ret = dict()
    for ch in x:
        if ch not in ret:
            ret[ch] = 1
        else:
            ret[ch] += 1
    return ret

def score(message:str)->float:
    occs = counts(message)
    freqs = dict()
    for ch in occs:
        freqs[ch] = occs[ch] / len(message)
    
    # find difference for each key (freqs vs ENGLISH_FREQS)
    total = 0
    for ch in freqs:
        actual = freqs[ch]
        if ch.upper() not in ENGLISH_FREQS:
            continue
        expected = ENGLISH_FREQS[ch.upper()]
        total += abs(expected - actual)

    return -total

if __name__ == '__main__':
    ciphertext = itob(0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736)
    
    all_messages = []

    # brute force all possible xor keys
    for i in range(0, 0xff+1):
        decrypted = xor(ciphertext, itob(i)*len(ciphertext))
        try:
            message = btos(decrypted)
        except:
            continue
        all_messages.append((message, score(message)))

    all_messages = sorted(all_messages, key=lambda item: item[1])
    print(all_messages)