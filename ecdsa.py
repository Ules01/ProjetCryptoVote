from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce():
    return randint(1, ORDER - 1)


def ECDSA_generate_keys():
    x = randint(1, ORDER - 2)
    Xu, Xv = mult(x, BaseU, BaseV, p)
    return Xu, Xv, x

def ECDSA_sign(m, x):
    s = 0
    r = 0
    while s == 0:
        while r == 0:
            k = ECDSA_generate_nonce()
            r, _ = mult(k, BaseU, BaseV, p)
            r = r % ORDER
        s = ((H(m) + x * r) * pow(k, -1, ORDER)) % ORDER
    return r, s


def ECDSA_verify(Xu, Xv, r, s, m):
    if 0 >= r or r >= ORDER or 0 >= s or s >= ORDER:
        return False
    print("first")
    u1 = (H(m) * pow(s, -1, ORDER)) % ORDER
    u2 = (r * pow(s, -1, ORDER)) % ORDER
    w1u, w1v = mult(u1, BaseU, BaseV, p)
    w2u, w2v = mult(u2, Xu, Xv, p)
    v, _ = add(w1u, w1v, w2u, w2v, p)
    v = v % ORDER
    return v == r