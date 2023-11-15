import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate a random key
def generate_key():
    return os.urandom(16)

# Encrypt using AES-128 in counter mode
def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)

# Compute cover set for a given subset of devices
def compute_cover_set(subset, n):
    cover_set = set()
    for device in subset:
        path = [device]
        while device > 1:
            device = device // 2
            path.append(device)
        cover_set.update(path)
    return cover_set

# Encrypt content based on the revoked devices
def encrypt_with_revocation(content, revoked_devices, total_devices):
    root_key = generate_key()
    content_key = generate_key()

    # Encrypt content key with root key
    encrypted_content_key = encrypt(root_key, content_key)[1]

    # Determine cover set of non-revoked devices
    non_revoked_devices = set(range(1, total_devices + 1)) - set(revoked_devices)
    cover_set = compute_cover_set(non_revoked_devices, total_devices)

    # Compute encryption keys for the cover set
    keys_for_cover_set = {node: generate_key() for node in cover_set}
    encrypted_keys = [encrypt(keys_for_cover_set[node], content_key)[1] for node in cover_set]

    return {
        "encrypted_content_key": encrypted_content_key,
        "encrypted_keys_for_cover_set": encrypted_keys
    }

# Example usage:
content = b'This is the content to encrypt.'
revoked_devices = {3, 7}  # Devices to revoke
total_devices = 8  # Total number of devices

encrypted_data = encrypt_with_revocation(content, revoked_devices, total_devices)
print(encrypted_data)
