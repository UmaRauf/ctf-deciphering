from Crypto.Cipher import AES
from binascii import unhexlify

# Extracted key and IV
key = unhexlify("429F2BE511E21B7A183F006872CD8F1C226C98E16506B9BEF580B0090CD392C1")
iv = unhexlify("4915D05DE2A44F337586554828C64356")

# Read the encrypted flag file
with open('flag.enc', 'rb') as f:
    ciphertext = f.read()

# Create the AES cipher object
cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt the ciphertext without unpadding
plaintext = cipher.decrypt(ciphertext)

# Write the decrypted content to a file
with open('decrypted_flag.txt', 'wb') as f:
    f.write(plaintext)

print("Decryption successful! Check 'decrypted_flag.txt' for the result.")
