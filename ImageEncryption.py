from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import numpy as np

# Function to load and display the image
def load_image(image_path):
    image = Image.open(image_path)
    image.show()  # This will open the image
    return image

# Function to convert the image to bytes
def image_to_bytes(image):
    image_bytes = np.array(image).tobytes()  # Convert image to bytes
    return image_bytes

# Function to convert bytes back to an image
def bytes_to_image(image_bytes, mode, size):
    image = Image.frombytes(mode, size, image_bytes)  # Convert bytes back to image
    return image

# Function to encrypt image bytes
def encrypt_image(image_bytes, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(image_bytes)
    return cipher.nonce, ciphertext, tag

# Function to decrypt the image bytes
def decrypt_image(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_bytes

# Function to save the encrypted data to a file
def save_encrypted_data(nonce, tag, ciphertext):
    with open('encrypted_image.bin', 'wb') as f:
        [f.write(x) for x in (nonce, tag, ciphertext)]

# Function to load the encrypted data from a file
def load_encrypted_data():
    with open('encrypted_image.bin', 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    return nonce, tag, ciphertext

# Main function tying everything together
def main():
    # Load the image
    image = load_image('image.jpg')  # Ensure 'image.jpg' is in the project folder

    # Convert the image to bytes
    image_bytes = image_to_bytes(image)

    # Generate a random AES key
    key = get_random_bytes(16)

    # Encrypt the image
    nonce, ciphertext, tag = encrypt_image(image_bytes, key)
    save_encrypted_data(nonce, tag, ciphertext)
    print("Image successfully encrypted and saved to 'encrypted_image.bin'.")

    # Load the encrypted data
    nonce, tag, ciphertext = load_encrypted_data()

    # Decrypt the image
    decrypted_bytes = decrypt_image(ciphertext, key, nonce, tag)

    # Convert bytes back to image and display it
    decrypted_image = bytes_to_image(decrypted_bytes, image.mode, image.size)
    decrypted_image.show()
    print("Image successfully decrypted and displayed.")

if __name__ == '__main__':
    main()
