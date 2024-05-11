from functools import reduce
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, bruteECLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from algebra import mod_inv, int_to_bytes
from random import randint

# Configuration
NUM_VOTERS = 10
NUM_CANDIDATES = 5
p = 2**255 - 19


# Generate keys for encryption and signing
voter_keys = [ECEG_generate_keys() for _ in range(NUM_VOTERS)]  # Generates (Uu, Uv, u) for each voter
signing_keys = [ECDSA_generate_keys() for _ in range(NUM_VOTERS)]  # Generates (public_key, private_key) pairs


# returns the encrypted vote for a given candidate
def vote_and_encrypt(candidate_index, Uu, Uv):
    # Create a vote pattern for a given candidate (1 for the selected candidate, 0 for others)
    vote_pattern = [1 if i == candidate_index else 0 for i in range(NUM_CANDIDATES)]
    print(f"Vote pattern {candidate_index}: {vote_pattern}")
    # Encrypt each vote in the vote pattern using the public key coordinates Uu and Uv
    encrypted_votes = [ECEG_encrypt(vote, Uu, Uv) for vote in vote_pattern]
    print(f"Encrypted votes {candidate_index}: {encrypted_votes}")
    return encrypted_votes


# Sign the encrypted ballot using the voter's ECDSA private key
def sign_ballot(ballot, private_key):
    # Create a hashable message from the encrypted ballot
    message = b''.join([int_to_bytes(c1u + c1v + c2u + c2v) for c1u, c1v, c2u, c2v in ballot])
    print(f"Message {private_key}: {message}")
    r, s = ECDSA_sign(message, private_key)
    signature = (r, s)
    return signature


# Xu and Xv are the public key coordinates, r and s are the signature, m is the message

# def ECDSA_verify(Xu, Xv, r, s, m):
def verify_ballot(Xu, Xv, signature, ballot):
    r, s = signature
    # Serialize the encrypted ballot into a hashable message
    message = b''.join([int_to_bytes(c1u + c1v + c2u + c2v) for c1u, c1v, c2u, c2v in ballot])
    print(f"Verifying message with public key ({Xu}, {Xv})")
    verified = ECDSA_verify(Xu, Xv, r, s, message)
    return verified

# Simulate voting
ballots = []
signatures = []
for i in range(NUM_VOTERS):
    candidate_choice = randint(0, NUM_CANDIDATES-1)
    Uu, Uv, _ = voter_keys[i]  # Public key components for encryption
    encrypted_ballot = vote_and_encrypt(candidate_choice, Uu, Uv)
    Xu, Xv, private_key = signing_keys[i]  # Public and private key for signing
    ballot_signature = sign_ballot(encrypted_ballot, private_key)
    ballots.append(encrypted_ballot)
    signatures.append((Xu, Xv, ballot_signature))  # Store public key components with signature

# Homomorphically combine encrypted votes and verify signatures
combined_votes = [
    reduce(
        lambda x, y: (x[0] + y[0], x[1] + y[1]), 
        [ballot[i] for ballot in ballots]
    ) for i in range(NUM_CANDIDATES)]


# Homomorphically combine encrypted votes
combined_votes = [
    reduce(
        lambda x, y: (x[0] + y[0], x[1] + y[1], x[2] + y[2], x[3] + y[3]),
        [ballot[i] for ballot in ballots]
    ) for i in range(NUM_CANDIDATES)
]

# Verify signatures
verified_ballots = [
    verify_ballot(signatures[i][0], signatures[i][1], signatures[i][2], ballots[i]) 
    for i in range(NUM_VOTERS)]


# Decrypt combined votes to find the final tally
final_tally = [bruteECLog(vote[2], vote[3], p) for vote in combined_votes]

print("Final tally:", final_tally)
print("Ballot verification results:", verified_ballots)

