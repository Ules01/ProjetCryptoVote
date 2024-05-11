from ecelgamal import EGencode, ECEG_Encrypt, ECEG_Decrypt, bruteECLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from algebra import mod_inv, int_to_bytes
from random import randint

# Configuration
NUM_VOTERS = 10
NUM_CANDIDATES = 5

# Generate keys for encryption and signing
encryption_keys = [EGencode(randint(0, 1)) for _ in range(NUM_VOTERS)]
signing_keys = [ECDSA_generate_keys() for _ in range(NUM_VOTERS)]

# vote and encrypt the vote Privacy
def vote_and_encrypt(candidate_index):
    # Create a vote pattern for a given candidate (1 for the selected candidate, 0 for others)
    vote_pattern = [1 if i == candidate_index else 0 for i in range(NUM_CANDIDATES)]
    encrypted_votes = [ECEG_Encrypt(vote) for vote in vote_pattern]
    return encrypted_votes

# Sign the encrypted ballot
def sign_ballot(ballot, voter_index):
    # Sign the encrypted ballot using the voter's ECDSA private key
    message = b''.join([int_to_bytes(ciphertext) for _, ciphertext in ballot])
    signature = ECDSA_sign(message, signing_keys[voter_index][1])
    return signature

def verify_ballot(ballot, signature, voter_index):
    # Verify the ballot signature
    message = b''.join([int_to_bytes(ciphertext) for _, ciphertext in ballot])
    return ECDSA_verify(message, signature, signing_keys[voter_index][0])

# Simulate voting
ballots = []
signatures = []
for i in range(NUM_VOTERS):
    candidate_choice = randint(0, NUM_CANDIDATES-1)
    encrypted_ballot = vote_and_encrypt(candidate_choice)
    ballot_signature = sign_ballot(encrypted_ballot, i)
    ballots.append(encrypted_ballot)
    signatures.append(ballot_signature)

# Homomorphically combine encrypted votes and verify signatures
combined_votes = [reduce(lambda x, y: (x[0] + y[0], x[1] + y[1]), [ballot[i] for ballot in ballots]) for i in range(NUM_CANDIDATES)]
verified_ballots = [verify_ballot(ballots[i], signatures[i], i) for i in range(NUM_VOTERS)]

# Decrypt combined votes to find the final tally
final_tally = [bruteECLog(*vote) for vote in combined_votes]

print("Final tally:", final_tally)
print("Ballot verification results:", verified_ballots)
