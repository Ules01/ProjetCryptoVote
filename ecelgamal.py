from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
#from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)

def ECEG_generate_keys():
    u = randint(1, p - 1)
    Uu, Uv = mult(u, BaseU, BaseV, p)
    return Uu, Uv, u


def ECEG_encrypt(m, Uu, Uv):
    r = randint(1, p - 1)
    c1u, c1v = mult(r, BaseU, BaseV, p)
    c2pu, c2pv = mult(r, Uu, Uv, p)
    Emu, Emv = EGencode(m)
    c2u, c2v = add(Emu, Emv, c2pu, c2pv, p)
    return c1u, c1v, c2u, c2v


def ECEG_decrypt(c1u, c1v, c2u, c2v, u):
    c1uu, c1uv = mult(u, c1u, c1v, p)
    return sub(c2u, c2v, c1uu, c1uv, p)


"""
m1 = 1
m2 = 0
m3 = 1
m4 = 1
m5 = 0

Uu, Uv, u = ECEG_generate_keys()
r1u, r1v, c1u, c1v = ECEG_encrypt(m1, Uu, Uv)
r2u, r2v, c2u, c2v = ECEG_encrypt(m2, Uu, Uv)
r3u, r3v, c3u, c3v = ECEG_encrypt(m3, Uu, Uv)
r4u, r4v, c4u, c4v = ECEG_encrypt(m4, Uu, Uv)
r5u, r5v, c5u, c5v = ECEG_encrypt(m5, Uu, Uv)

r12u, r12v = add(r1u, r1v, r2u, r2v, p)
r34u, r34v = add(r3u, r3v, r4u, r4v, p)
ru, rv = add(r12u, r12v, r34u, r34v, p)
c12u, c12v = add(c1u, c1v, c2u, c2v, p)
c34u, c34v = add(c3u, c3v, c4u, c4v, p)
cu, cv = add(c12u, c12v, c34u, c34v, p)

m61, m62 = ECEG_decrypt(ru, rv, cu, cv, u)
print(bruteECLog(m61, m62, p))

"""