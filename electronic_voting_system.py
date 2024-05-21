from functools import reduce
from random import randint
from rfc7748 import add, mult, computeVcoordinate
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from algebra import int_to_bytes
from utils import time_it
import math






# Configuration
p = 2**255 - 19

NUMBER_VOTERS = 10
NUMBER_CANDIDATES = 5

encrypt_keys = []
for i in range(NUMBER_CANDIDATES):
    encrypt_keys.append(ECEG_generate_keys())


def sign_vote(encrypted_vote, private_key):
    ballot_message = str(encrypted_vote).encode()  # Encode the ballot data
    signature = ECDSA_sign(ballot_message, private_key)
    signature
    return signature

def verify_vote(encrypted_vote, signature, public_key):
    ballot_message = str(encrypted_vote).encode()
    Xu, Xv = public_key
    verified = ECDSA_verify(Xu, Xv, signature[0], signature[1], ballot_message)
    return verified

def generate_single_vote():
    vote_index = randint(0, NUMBER_CANDIDATES - 1)
    vote = [0] * NUMBER_CANDIDATES
    vote[vote_index] = 1
    print(vote)
    encrypt_vote = []
    for i in range(NUMBER_CANDIDATES): 
        Uu, Uv, _ = encrypt_keys[i]
        encrypt_vote.append(ECEG_encrypt(vote[i], Uu, Uv))
    
    # Generate keys for signing
    signer_keys = ECDSA_generate_keys()
    public_keys = (signer_keys[0], signer_keys[1])
    private_keys = signer_keys[2]
    signature = sign_vote(encrypt_vote, private_keys)
    return encrypt_vote, signature, public_keys

def generate_votes():
    encrypt_votes = []
    print("votes:")
    for _ in range(NUMBER_VOTERS):
        encrypt_vote, signature, public_key = generate_single_vote()
        if(verify_vote(encrypt_vote, signature, public_key)):
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

def decrypt_and_count_votes(encrypted_ballots):
    results = []
    uIndex = 0
    for encrypts in encrypted_ballots:
        _, __, u = encrypt_keys[uIndex]
        ru, rv, cu, cv = encrypts[0]
        for i in range(1, len(encrypts)):
            oldRu, oldRv, oldCu, oldCv = encrypts[i]
            ru, rv = add(ru, rv, oldRu, oldRv, p)
            cu, cv = add(cu, cv, oldCu, oldCv, p)

        m1, m2 = ECEG_decrypt(ru, rv, cu, cv, u)
        results.append(bruteECLog(m1, m2, p))
        uIndex = uIndex + 1
    return results




def simulate_electronic_voting():

    # Generate and print votes
    votes = generate_votes()

    # Encrypt votes 
    encrypted_ballots = create_ballots(votes)
    
    # Generate keys for signing
    #signer_keys = [ECDSA_generate_keys() for _ in range(num_voters)]
    #public_keys = [(keys[0], keys[1]) for keys in signer_keys]
    #private_keys = [keys[2] for keys in signer_keys]

    #signatures = sign_ballots(encrypted_ballots, private_keys)

    # Decrypt and count votes
    print("Number of votes:")
    final_tally = decrypt_and_count_votes(encrypted_ballots)
    print(final_tally)

    # Verify the signatures of the encrypted ballots
    #verification_results = verify_ballots(encrypted_ballots, signatures, public_keys)
    #print("Verification Results:")
    #print(verification_results)

simulate_electronic_voting()