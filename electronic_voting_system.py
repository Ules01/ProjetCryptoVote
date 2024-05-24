from functools import reduce
from random import randint
from rfc7748 import add, mult, computeVcoordinate
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog
from elgamal import EGM_encrypt, EGA_encrypt, EG_generate_keys, PARAM_P, EG_decrypt, bruteLog, PARAM_G, bruteLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from algebra import int_to_bytes, mod_inv
from utils import time_it
import math

# Configuration
p = 2**255 - 19

NUMBER_VOTERS = 10
NUMBER_CANDIDATES = 5

encrypt_keys = []

def generate_keys(var_encryption):
    encrypt_keys.clear()  # Clear any existing keys
    if var_encryption == "ECG":
        for i in range(NUMBER_CANDIDATES):
            encrypt_keys.append(ECEG_generate_keys())
    else:
        for i in range(NUMBER_CANDIDATES):
            encrypt_keys.append(EG_generate_keys())

def sign_vote(encrypted_vote, private_key):
    ballot_message = str(encrypted_vote).encode()  # Encode the ballot data
    signature = ECDSA_sign(ballot_message, private_key)
    return signature

def verify_vote(encrypted_vote, signature, public_key):
    ballot_message = str(encrypted_vote).encode()
    Xu, Xv = public_key
    verified = ECDSA_verify(Xu, Xv, signature[0], signature[1], ballot_message)
    return verified

def generate_single_vote(var_encryption):
    vote_index = randint(0, NUMBER_CANDIDATES - 1)
    vote = [0] * NUMBER_CANDIDATES
    vote[vote_index] = 1
    print(vote)
    encrypt_vote = []
    for i in range(NUMBER_CANDIDATES):
        if var_encryption == "ECG":
            Uu, Uv, _ = encrypt_keys[i]
            encrypt_vote.append(ECEG_encrypt(vote[i], Uu, Uv))
        else:  # ElGamal encryption
            U, u = encrypt_keys[i]
            #encrypt_vote.append((r, c))
            encrypt_vote.append(EGA_encrypt(vote[i], U))

    # Generate keys for signing
    signer_keys = ECDSA_generate_keys()
    public_keys = (signer_keys[0], signer_keys[1])
    private_keys = signer_keys[2]
    signature = sign_vote(encrypt_vote, private_keys)
    return encrypt_vote, signature, public_keys

def generate_votes(var_encryption):
    encrypt_votes = []
    print("votes:")
    for _ in range(NUMBER_VOTERS):
        encrypt_vote, signature, public_key = generate_single_vote(var_encryption)
        if verify_vote(encrypt_vote, signature, public_key):
            print("Vote accepted")
            encrypt_votes.append(encrypt_vote)
    print()
    return encrypt_votes

def create_ballots(votes):
    ballots = [[0] * NUMBER_VOTERS for _ in range(NUMBER_CANDIDATES)]
    for i in range(NUMBER_CANDIDATES):
        for j in range(NUMBER_VOTERS):
            ballots[i][j] = votes[j][i]
    return ballots

def decrypt_and_count_votes(encrypted_ballots, var_encryption):
    results = []
    uIndex = 0
    for encrypts in encrypted_ballots:
        if var_encryption == "ECG":
            _, __, u = encrypt_keys[uIndex]
            ru, rv, cu, cv = encrypts[0]
            for i in range(1, len(encrypts)):
                oldRu, oldRv, oldCu, oldCv = encrypts[i]
                ru, rv = add(ru, rv, oldRu, oldRv, p)
                cu, cv = add(cu, cv, oldCu, oldCv, p)
            m1, m2 = ECEG_decrypt(ru, rv, cu, cv, u)
            results.append(bruteECLog(m1, m2, p))
            uIndex += 1
        else:  # ElGamal decryption
            U, u = encrypt_keys[uIndex]
            r, c = encrypts[0]
            
            for i in range(1, len(encrypts)):   
                oldR, oldC = encrypts[i]
                r = (r * oldR) % PARAM_P
                c = (c * oldC) % PARAM_P
            
            m = EG_decrypt(r,c,u)
            m1 = bruteLog(PARAM_G, m, PARAM_P)
            results.append(m1)
            uIndex += 1
    return results

def simulate_electronic_voting():
    # choosing the Encryption/Signature
    v1 = False
    v2 = False
    var_encryption = ""
    var_signature = ""

    while not v1:
        var_encryption = input("Type EG for El gamal encryption or ECG for Ec El Gamal: \n").strip().upper()
        if var_encryption in ['EG', 'ECG']:
            v1 = True
        else:
            print("Try again.")

    while not v2:
        var_signature = input("Type DSA for DSA Signature or ECDSA for ECDSA Signature: \n").strip().upper()
        if var_signature in ['DSA', 'ECDSA']:
            v2 = True
        else:
            print("Try again.")

    # Generate keys for encryption
    generate_keys(var_encryption)

    # Generate and print votes
    votes = generate_votes(var_encryption)

    # Encrypt votes
    encrypted_ballots = create_ballots(votes)

    # Decrypt and count votes
    print("Number of votes:")
    final_tally = decrypt_and_count_votes(encrypted_ballots, var_encryption)
    print(final_tally)

simulate_electronic_voting()

