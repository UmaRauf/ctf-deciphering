import hashlib
import itertools
import string

# Target MD5 hash
target_hash = '7ef46b990df3001c1b5165114e8ebb52'

# Function to generate MD5 hash for a string
def generate_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# Function to brute-force MD5 hash
def brute_force_md5(target_hash, length=4):
    characters = string.ascii_lowercase + string.digits  # Adjust to match the character set you're testing
    for password_tuple in itertools.product(characters, repeat=length):
        password = ''.join(password_tuple)
        if generate_md5(password) == target_hash:
            return password
    return None

# Try to brute-force the hash (you can adjust length based on your guesses)
password = brute_force_md5(target_hash)
if password:
    print(f"Found the password: {password}")
else:
    print("Password not found.")
