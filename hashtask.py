import struct
import io

def leftRotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff 

def processChunk(chunk, h0, h1, h2, h3, h4):
    w = [0] * 80
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    for i in range(16, 80):
        w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    for i in range(80):
        if 0 <= i <= 18:
            f = d ^ (b & (c ^ d))
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
    a, b, c, d, e = ((leftRotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, leftRotate(b, 30), c, d)
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4

class SHA_1:
    dSize = 20
    bSize = 64

    def __init__(self):
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )
        self._unprocessed = b''
        self._messageLength = 0

    def update(self, arg):
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))
        while len(chunk) == 64:
            self._h = processChunk(chunk, *self._h)
            self._messageLength += 64
            chunk = arg.read(64)
        self._unprocessed = chunk
        return self

    def digest(self):
        return b''.join(struct.pack(b'>I', h) for h in self.produceDigest())

    def hexdigest(self):
        return '%08x%08x%08x%08x%08x' % self.produceDigest()

    def produceDigest(self):
        message = self._unprocessed
        messageLength = self._messageLength + len(message)
        message += b'\x80'
        message += b'\x00' * ((56 - (messageLength + 1) % 64) % 64)
        messageBitLength = messageLength * 8
        message += struct.pack(b'>Q', messageBitLength)
        h = processChunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return processChunk(message[64:], *h)

def sha1(data):
    return SHA_1().update(data).hexdigest()

