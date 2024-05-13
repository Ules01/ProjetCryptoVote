import numpy as np
from algebra import mod_inv, int_to_bytes
from Crypto.Hash import SHA256
from random import randint, choice
from dsa import DSA_generate_keys, DSA_sign, DSA_verify
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from elgamal import EG_generate_keys, EGM_encrypt, EGA_encrypt, EG_decrypt, PARAM_P
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt


def generate_keys_for_voters(num_voters, use_ecdsa):
    voters_keys = {}
    for i in range(num_voters):
        if use_ecdsa:
            voters_keys[i] = ECDSA_generate_keys()
        else:
            voters_keys[i] = DSA_generate_keys()
    return voters_keys



def encrypt_votes(num_voters, use_ec):
    encrypted_votes = {}
    for i in range(num_voters):
        vote_index = randint(0, 4)
        vote = [0] * 5
        vote[vote_index] = 1
        print(f"Votes for voter {i}: {vote}")  
        if use_ec:
            Uu, Uv, u = ECEG_generate_keys()
            encrypted_votes[i] = [ECEG_encrypt(v, Uu, Uv) for v in vote]
        else:
            U, u = EG_generate_keys()
            encrypted_votes[i] = [EGA_encrypt(v, U) for v in vote]
    return encrypted_votes

def sign_ballots(encrypted_votes, keys, use_ecdsa):
    signed_ballots = {}
    for voter_id, votes in encrypted_votes.items():
        ballot = ''.join(str(v) for v in votes)  
        # We just concatenated the votes for the signature
        if use_ecdsa:
            r, s = ECDSA_sign(ballot, keys[voter_id][2])
        else:
            r, s = DSA_sign(ballot, keys[voter_id][1])
        signed_ballots[voter_id] = (votes, (r, s))
    return signed_ballots

def aggregate_votes(signed_ballots, use_ec):
    # Initialize aggregated votes with the encryption of zero, not just (0, 0)
    if use_ec:
        # Encrypt zero using EC El Gamal encryption scheme
        zero_encrypted = [ECEG_encrypt(0, *ECEG_generate_keys()[:2]) for _ in range(5)]
    else:
        # Encrypt zero using standard El Gamal encryption scheme
        zero_encrypted = [EGA_encrypt(0, *EG_generate_keys()[:1]) for _ in range(5)]
    aggregated_votes = zero_encrypted  # This initializes to valid ciphertexts of zero

    for _, votes in signed_ballots.items():
        for i, vote_tuple in enumerate(votes[0]):
            print(f"Aggregating vote {vote_tuple} into {aggregated_votes[i]}")  # Debug: Aggregation step
            if use_ec:
                aggregated_votes[i] = (
                    (aggregated_votes[i][0] + vote_tuple[0]) % PARAM_P,
                    (aggregated_votes[i][1] + vote_tuple[1]) % PARAM_P
                )
            else:
                aggregated_votes[i] = (
                    (aggregated_votes[i][0] * vote_tuple[0]) % PARAM_P,
                    (aggregated_votes[i][1] * vote_tuple[1]) % PARAM_P
                )
    return aggregated_votes


def verify_ballots(signed_ballots, keys, use_ecdsa=False):
    for voter_id, (votes, (r, s)) in signed_ballots.items():
        ballot = ''.join(str(v) for v in votes)
        if use_ecdsa:
            if not ECDSA_verify(keys[voter_id][0], keys[voter_id][1], r, s, ballot):
                return False
        else:
            if not DSA_verify(keys[voter_id][0], r, s, ballot):
                return False
    return True
#vote simulation 
num_voters = 10 
use_ecdsa = False  # Change to True to use ECDSA and EC El Gamal
use_ec = False  

keys = generate_keys_for_voters(num_voters, use_ecdsa)
encrypted_votes = encrypt_votes(num_voters, use_ec)
signed_ballots = sign_ballots(encrypted_votes, keys, use_ecdsa)

if verify_ballots(signed_ballots, keys, use_ecdsa):
    aggregated_votes = aggregate_votes(signed_ballots, use_ec)
else:
    print("Verification of signatures failed")

