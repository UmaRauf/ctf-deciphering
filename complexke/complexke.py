import base64
from hashlib import md5, sha256
from Crypto.Cipher import AES

# ================================
# Configuration Parameters
# ================================
STEP3_RESPONSE = "VTJGc2RHVmtYMTlPN09vVDJLWDE0Unh2b2JVeGNJUSs5V2p6UlNIVFFhVEFOQkNhb1dLeDBtSW1UZ1J4M2dWUWZmdUFaNXhjOGF0NEcyWmxSbG1MaEE9PSxVMkZzZEdWa1gxL2h2N0ZKLzNoaUgyblRvZytMazYzY0hoRm1meWN0b1FvcU1lNkNzcEtkdHpnY05BUVpBZDR3"
KES = 1788279208104052375212791311701435195696  # Attacker's Key

# ================================
# Helper Functions
# ================================
def base64_decode(data: str) -> bytes:
    """Base64 decode a string."""
    return base64.b64decode(data)

def convert_kes_to_bytes(kes: int) -> bytes:
    """Convert KES (integer) to bytes."""
    return kes.to_bytes((kes.bit_length() + 7) // 8, byteorder='big')

def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
    """Derive key and IV using OpenSSL's EVP_BytesToKey method."""
    dtot = b''
    d = b''
    while len(dtot) < (key_len + iv_len):
        d = md5(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len + iv_len]

def decrypt_openssl(encrypted_data: bytes, password: bytes) -> bytes:
    """Decrypt OpenSSL AES-256-CBC encrypted data."""
    if encrypted_data[:8] != b"Salted__":
        raise ValueError("Missing 'Salted__' header.")

    salt = encrypted_data[8:16]
    ciphertext = encrypted_data[16:]
    key, iv = evp_bytes_to_key(password, salt, 32, 16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    pad_len = decrypted[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding.")
    return decrypted[:-pad_len]
def decrypt_openssl_debug(encrypted_data: bytes, password: bytes) -> bytes:
    """Decrypt OpenSSL AES-256-CBC encrypted data with debug output."""
    if encrypted_data[:8] != b"Salted__":
        raise ValueError("Missing 'Salted__' header.")

    salt = encrypted_data[8:16]
    ciphertext = encrypted_data[16:]
    key, iv = evp_bytes_to_key(password, salt, 32, 16)

    print(f"Derived Key: {key.hex()}")
    print(f"Derived IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    print(f"Decrypted raw output: {decrypted.hex()}")
    return decrypted  # Return decrypted data without padding validation for debugging

# ================================
# Main Process
# ================================

# Step 1: Decode the Step 3 Response
print("=== Step 1: Decoding Step 3 Response ===")
decoded_response = base64_decode(STEP3_RESPONSE).decode('utf-8')
encrypted_K_b64, encrypted_s_b64 = decoded_response.split(',')
print(f"Encrypted K (Base64): {encrypted_K_b64}")
print(f"Encrypted #s (Base64): {encrypted_s_b64}")

# Step 2: Convert KES to Bytes
print("=== Step 2: Converting KES to Bytes ===")
kes_raw_bytes = convert_kes_to_bytes(KES)
kes_hashed = sha256(kes_raw_bytes).digest()
print(f"KES (raw bytes): {kes_raw_bytes.hex()}")
print(f"KES (SHA-256 hashed): {kes_hashed.hex()}")

# Step 3: Decrypt {K}KES to Obtain Session Key K
print("=== Step 3: Decrypting {K}KES ===")
encrypted_K = base64_decode(encrypted_K_b64)

try:
    decrypted_K_raw = decrypt_openssl_debug(encrypted_K, kes_hashed)
    # Truncate or adjust key length if necessary
    decrypted_K = decrypted_K_raw[:32]  # Assuming AES-256 key length
    print(f"Decrypted Session Key K (adjusted): {decrypted_K.hex()}")
except Exception as e:
    print(f"Failed to decrypt K: {e}")
    exit(1)
# Step 3: Decrypt {K}KES to Obtain Session Key K
print("=== Step 3: Decrypting {K}KES ===")
encrypted_K = base64_decode(encrypted_K_b64)

try:
    decrypted_K_raw = decrypt_openssl_debug(encrypted_K, kes_hashed)
    # Truncate or adjust key length if necessary
    decrypted_K = decrypted_K_raw[:32]  # Assuming AES-256 key length
    print(f"Decrypted Session Key K (adjusted): {decrypted_K.hex()}")
except Exception as e:
    print(f"Failed to decrypt K: {e}")
    exit(1)



# Step 4: Decrypt {#s}K to Obtain Secret #s
print("=== Step 4: Decrypting {#s}K ===")
encrypted_s = base64_decode(encrypted_s_b64)

try:
    decrypted_s_raw = decrypt_openssl_debug(encrypted_s, decrypted_K)
    # Remove padding safely if present
    pad_len = decrypted_s_raw[-1]
    if 1 <= pad_len <= 16:  # Typical PKCS#7 padding
        secret_s = decrypted_s_raw[:-pad_len].decode('utf-8')
    else:
        secret_s = decrypted_s_raw.decode('utf-8')  # Assume no padding
    print(f"Secret #s: {secret_s}")
except Exception as e:
    print(f"Failed to decrypt #s: {e}")
    exit(1)


print("=== Decryption Complete ===")
