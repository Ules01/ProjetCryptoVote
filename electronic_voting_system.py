from functools import reduce
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt,bruteECLog
from random import randint
from rfc7748 import add

# Configuration
NUM_VOTERS = 5
NUM_CANDIDATES = 2
p = 2**255 - 19

votes = []
for i in range(NUM_VOTERS):
    voteIndex = randint(0, NUM_CANDIDATES - 1)
    vote = [0] * NUM_CANDIDATES
    vote[voteIndex] = 1
    votes.append(vote)


print("Votes:")
for vote in votes:
    print(vote)
print()

ballots = [[0] * NUM_VOTERS for _ in range(NUM_CANDIDATES)]
for i in range(NUM_VOTERS):
    for j in range (NUM_CANDIDATES):
        ballots[j][i] = votes[i][j]

print("Ballots:")
for ballot in ballots:
    print(ballot)
print()

#ballots = [[1, 0, 1, 1, 0]]

print("Number of votes:")
for ballot in ballots:
    #encrypt
    Uu, Uv, u = ECEG_generate_keys()
    encrypts = []
    for vote in ballot:
        encrypts.append(ECEG_encrypt(vote, Uu, Uv))

    #decrypt
    ru, rv, cu, cv = encrypts[0]
    for i in range(1, NUM_VOTERS):
        oldRu, oldRv, oldCu, oldCv = encrypts[i]
        ru, rv = add(ru, rv, oldRu, oldRv, p)
        cu, cv = add(cu, cv, oldCu, oldCv, p)

    m1, m2 = ECEG_decrypt(ru, rv, cu, cv, u)
    print(bruteECLog(m1, m2, p))

