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

def generate_votes(num_voters, num_candidates):
    votes = []
    for _ in range(num_voters):
        vote_index = randint(0, num_candidates - 1)
        vote = [0] * num_candidates
        vote[vote_index] = 1
        votes.append(vote)
    return votes

def encrypt_votes(votes, num_voters, num_candidates):
    ballots = [[0] * num_voters for _ in range(num_candidates)]
    for i in range(num_voters):
        for j in range(num_candidates):
            ballots[j][i] = votes[i][j]

    encrypted_ballots = []
    for ballot in ballots:
        Uu, Uv, u = ECEG_generate_keys()
        encrypts = []
        for vote in ballot:
            encrypts.append(ECEG_encrypt(vote, Uu, Uv))
        encrypted_ballots.append((encrypts, u))
    return encrypted_ballots

def decrypt_and_count_votes(encrypted_ballots):
    results = []
    for encrypts, u in encrypted_ballots:
        ru, rv, cu, cv = encrypts[0]
        for i in range(1, len(encrypts)):
            oldRu, oldRv, oldCu, oldCv = encrypts[i]
            ru, rv = add(ru, rv, oldRu, oldRv, p)
            cu, cv = add(cu, cv, oldCu, oldCv, p)

        m1, m2 = ECEG_decrypt(ru, rv, cu, cv, u)
        results.append(bruteECLog(m1, m2, p))
    return results

def sign_ballots(encrypted_ballots, private_keys):
    signatures = []
    for encrypted_ballot, priv_key in zip(encrypted_ballots, private_keys):
        ballot_message = str(encrypted_ballot).encode()  # Encode the ballot data
        signature = ECDSA_sign(ballot_message, priv_key)
        signatures.append(signature)
    return signatures

def verify_ballots(encrypted_ballots, signatures, public_keys):
    verification_results = []
    for encrypted_ballot, signature, pub_key in zip(encrypted_ballots, signatures, public_keys):
        ballot_message = str(encrypted_ballot).encode()
        Xu, Xv = pub_key
        verified = ECDSA_verify(Xu, Xv, signature[0], signature[1], ballot_message)
        verification_results.append(verified)
    return verification_results



def simulate_electronic_voting():
    num_voters = 10
    num_candidates = 5

    # Generate and print votes
    votes = generate_votes(num_voters, num_candidates)
    print("Votes:")
    for vote in votes:
        print(vote)
    print()

    # Encrypt votes 
    encrypted_ballots = encrypt_votes(votes, num_voters, num_candidates)
    
    # Generate keys for signing
    signer_keys = [ECDSA_generate_keys() for _ in range(num_voters)]
    public_keys = [(keys[0], keys[1]) for keys in signer_keys]
    private_keys = [keys[2] for keys in signer_keys]

    signatures = sign_ballots(encrypted_ballots, private_keys)

    # Decrypt and count votes
    print("Number of votes:")
    final_tally = decrypt_and_count_votes(encrypted_ballots)
    print(final_tally)

    # Verify the signatures of the encrypted ballots
    verification_results = verify_ballots(encrypted_ballots, signatures, public_keys)
    print("Verification Results:")
    print(verification_results)

simulate_electronic_voting()