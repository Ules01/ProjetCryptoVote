from functools import reduce
from random import randint
from rfc7748 import add, mult, computeVcoordinate
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from algebra import int_to_bytes
from utils import time_it
import math

# Configuration
NUM_VOTERS = 10
NUM_CANDIDATES = 5
p = 2**255 - 19
BaseU = 9
BaseV = computeVcoordinate(BaseU)


# ecelGamal et ECDSA key generation

voter_keys = [ECEG_generate_keys() for _ in range(NUM_VOTERS)]
signer_keys = [ECDSA_generate_keys() for _ in range(NUM_VOTERS)]

@time_it
def encrypt_votes(voter_keys):
    ballots = []
    for keys in voter_keys:
        Uu, Uv, _ = keys
        vote = [randint(0, 1) for _ in range(NUM_CANDIDATES)]
        encrypted_ballot = [ECEG_encrypt(v, Uu, Uv) for v in vote]
        ballots.append(encrypted_ballot)
    return ballots

@time_it
def sign_ballots(ballots, signer_keys):
    signatures = []
    for ballot, keys in zip(ballots, signer_keys):
        Xu, Xv, private_key = keys
        ballot_message = b''.join([int_to_bytes(vote[2] + vote[3]) for vote in ballot])
        signature = ECDSA_sign(ballot_message, private_key)
        signatures.append((Xu, Xv, signature))
    return signatures


def baby_step_giant_step(G, h, p):
    m = int(math.sqrt(p)) + 1  # Step size
    baby_steps = {}
    
    # Baby steps
    current_point = (1, 0)  # Start with the identity element of the elliptic curve, which acts as zero.
    for j in range(m):
        if current_point not in baby_steps:
            baby_steps[current_point] = j
        current_point = mult(j+1, G[0], G[1], p)  # Compute j*G

    # Giant steps
    Gm = mult(m, G[0], G[1], p)  # Compute m*G
    neg_Gm = (Gm[0], -Gm[1] % p)  # Compute -m*G by negating the y-coordinate

    current_point = h
    for i in range(m):
        if current_point in baby_steps:
            return i * m + baby_steps[current_point]  # Logarithm found
        current_point = add(current_point[0], current_point[1], neg_Gm[0], neg_Gm[1], p)  # h - i*m*G

    return None  # Logarithm not found, handle this case appropriately



@time_it
def combine_and_decrypt_ballots(ballots, voter_keys):
    # Initialize combined results with zeros (point at infinity)
    combined_r = [(0, 0)] * NUM_CANDIDATES
    combined_c = [(0, 0)] * NUM_CANDIDATES

    for ballot in ballots:
        for i in range(NUM_CANDIDATES):
            ru, rv, cu, cv = ballot[i]
            combined_r[i] = add(combined_r[i][0], combined_r[i][1], ru, rv, p)
            combined_c[i] = add(combined_c[i][0], combined_c[i][1], cu, cv, p)

    decrypted_votes = []
    for r, c in zip(combined_r, combined_c):
        decrypted = ECEG_decrypt(r[0], r[1], c[0], c[1], voter_keys[0][2])  # Assuming all use the same key for simplicity
        decrypted_votes.append(decrypted)

    print("decrypted_votes", decrypted_votes)

    # final_tally = []
    # for dec in decrypted_votes:
    #     result = bruteECLog(dec[0], dec[1], p)
    #     final_tally.append(result)


    
    final_tally = []
    for i in range(NUM_CANDIDATES):
        r, c = decrypted_votes[i]
        final_tally.append(baby_step_giant_step((BaseU, BaseV), r, p))
        print("final_tally", final_tally)
        break

    return final_tally



# Xu and Xv are the public key coordinates, r and s are the signature, m is the message
# def ECDSA_verify(Xu, Xv, r, s, m):
@time_it
def verify_ballots(ballots, signatures):
    verification_results = []
    for ballot, (Xu, Xv, signature) in zip(ballots, signatures):
        message = b''.join([int_to_bytes(vote[2] + vote[3]) for vote in ballot])
        verified = ECDSA_verify(Xu, Xv, signature[0], signature[1], message)
        verification_results.append(verified)
    return verification_results


# Simulate voting
def simulate_electronic_voting():
    ballots = encrypt_votes(voter_keys)
    signatures = sign_ballots(ballots, signer_keys)
    final_tally = combine_and_decrypt_ballots(ballots, voter_keys)
    verification_results = verify_ballots(ballots, signatures)

    print("Final tally of votes:", final_tally)
    print("Verification results:", verification_results)

simulate_electronic_voting()
