b = 0x7998bfda

def rotl32(x, n):
    return ((x << n) | (x >> (32-n))) & 0xffffffff

print(f"before {hex(b)}")
print(f"after {hex(rotl32(b, 7))}")
