import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
import io

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

# Image to Bytes
def image_to_bytes(image_path):
    with Image.open(image_path) as img:
        with io.BytesIO() as byte_arr:
            img.save(byte_arr, format=img.format)
            return byte_arr.getvalue()

# Bytes to Image
def bytes_to_image(byte_data, output_path):
    with Image.open(io.BytesIO(byte_data)) as img:
        img.save(output_path)

# Encrypt content based on the revoked devices
def encrypt_with_revocation(image_path, revoked_devices, total_devices):
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

    # Convert the image to bytes and encrypt
    image_bytes = image_to_bytes(image_path)
    encrypted_image_iv, encrypted_image = encrypt(root_key, image_bytes)

    return {
        "encrypted_content": encrypted_image,
        "encrypted_content_iv": encrypted_image_iv,
        "encrypted_content_key": encrypted_content_key,
        "encrypted_keys_for_cover_set": encrypted_keys
    }

# Example usage
image_path = 'path_to_your_image.jpg'  # Replace with your image path
output_path = 'encrypted_image.jpg'
revoked_devices = {3, 7}  # Devices to revoke
total_devices = 8  # Total number of devices

encrypted_data = encrypt_with_revocation(image_path, revoked_devices, total_devices)

# Save the encrypted image
bytes_to_image(encrypted_data['encrypted_content'], output_path)

print("Image encryption completed. Check the encrypted image.")
