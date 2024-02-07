
# -*- coding: utf-8 -*-

import binascii
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random
import os

backend = default_backend()

# Create a function that converts a hex string to base64
def hex_to_base64(hex_string: str) -> str:
    """Convert a hex string to base64"""
    b64_str = base64.b64encode(binascii.unhexlify(hex_string))
    return b64_str

# Write a function that takes two equal-length buffers and produces their XOR combination
def hex_xor(buffer1: bytes, buffer2: bytes) -> bytes:
    """Produce the XOR combination of two equal-length buffers"""
    return bytes([b1 ^ b2 for b1, b2 in zip(buffer1, buffer2)])

# Create a dictionary containing letters of the alphabet and their corresponding frequency in the English language
letter_freq = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702, "f": 0.02228,
    "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153, "k": 0.00772, "l": 0.04025,
    "m": 0.02406, "n": 0.06749, "o": 0.07507, "p": 0.01929, "q": 0.00095, "r": 0.05987,
    "s": 0.06327, "t": 0.09056, "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150,
    "y": 0.01974, "z": 0.00074, " ": 0.13000
}

def score_text(text: bytes) -> float:
    """Score the text based on the frequency of English letters"""
    score = 0
    text = text.decode("utf-8", errors='ignore')
    for char in text:
        if char.lower() in letter_freq:
            score += letter_freq[char.lower()]
    return score

def break_single_byte_xor(ciphertext: bytes) -> bytes:
    """Break a single-byte XOR cipher"""
    scores = {}
    for i in range(256):
        keystream = bytes([i] * len(ciphertext))
        plaintext = hex_xor(ciphertext, keystream)
        scores[i] = score_text(plaintext)
    key = max(scores, key=scores.get)
    message = hex_xor(ciphertext, bytes([key] * len(ciphertext)))
    return {"message": message, "key": key}

def detect_single_char_xor(filename: str) -> bytes:
    """Detect the single character XOR cipher from a file"""
    candidates = {}
    with open(filename) as data:
        for line in data:
            ciphertext = binascii.unhexlify(line.strip())
            plaintext = break_single_byte_xor(ciphertext)['message']
            candidates[plaintext] = score_text(plaintext)
    best_candidate = max(candidates, key=candidates.get)
    return best_candidate

def repeating_key_xor(ciphertext: bytes, key: bytes) -> bytes:
    """Break a repeating-key XOR cipher"""
    keystream = key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)]
    return binascii.hexlify(hex_xor(ciphertext, keystream))

def hamming_distance(s1: bytes, s2: bytes) -> int:
    """Calculate the Hamming distance between two strings"""
    return sum([bin(byte).count('1') for byte in hex_xor(s1, s2)])

def break_repeating_key_xor(filename: str) -> bytes:
    """Break a repeating-key XOR cipher from a file"""
    with open(filename) as data:
        ciphertext = base64.b64decode(data.read())
        
        # Determine the top 3 key sizes
        distances = {}
        for keysize in range(2, 41):
            blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)][:4]
            distance = 0
            for i in range(len(blocks) - 1):
                distance += hamming_distance(blocks[i], blocks[i+1])
            distances[keysize] = distance / keysize
        possible_key_sizes = sorted(distances, key=distances.get)[:3]

        # Determine the most likely key for each possible key size
        possible_solutions = {}
        for k in possible_key_sizes:
            key = b''
            parts = []
            for i in range(k):
                part = break_single_byte_xor(ciphertext[i::k])
                key += bytes([part['key']])
            possible_solutions[k] = (binascii.unhexlify(repeating_key_xor(ciphertext, key)), key)
        
        # Return the most likely solution
        solution = possible_solutions[max(possible_solutions, key=lambda x: score_text(possible_solutions[x][0]))]
        # print("Key:", solution[1].decode())
        # print("Plaintext:", solution[0].decode())
        return solution

def break_aes_128_ecb(filename: str) -> bytes:
    """Break an AES-128 ECB cipher from a file"""
    with open(filename) as data:
        ciphertext = base64.b64decode(data.read())
        key = b'YELLOW SUBMARINE'
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

def has_repeated_blocks(ciphertext: bytes, blocksize: int=16) -> bool:
    """Check if a ciphertext has repeated blocks"""
    blocks = [ciphertext[i:i+blocksize] for i in range(0, len(ciphertext), blocksize)]
    num_dupes =  len(blocks) - len(set(blocks))
    return bool(num_dupes)

def test_ecb_128(ciphertexts: bytes, blocksize: int=16) -> bool:
    """Test if a ciphertext is encrypted using AES-128 ECB mode"""
    hits = [ctxt for ctxt in ciphertexts if has_repeated_blocks(ctxt)]
    return bool(len(hits))

def detect_aes_128_ecb(filename: str) -> bool:
    """Detect an AES-128 ECB cipher from a file"""
    with open(filename) as data:
        ciphertexts = [binascii.unhexlify(line.strip()) for line in data]
        return test_ecb_128(ciphertexts)

def pad_pkcs7(data: bytes, blocksize: int=20) -> bytes:
    """Pad data using PKCS#7"""
    padding = (blocksize - len(data)) % blocksize
    return data + (bytes([padding]) * padding)

def unpad_pkcs7(data: bytes) -> bytes:
    """Unpad data using PKCS#7"""
    padding = data[-1]
    if all([byte == padding for byte in data[-padding:]]):
        return data[:-padding]
    else:
        return data

def encrypt_aes_128_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext using AES-128 ECB"""
    padded_msg = pad_pkcs7(plaintext, 16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_msg) + encryptor.finalize()

def decrypt_aes_128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 ECB"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_pkcs7(plaintext)

def encrypt_aes_128_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt plaintext using AES-128 CBC"""
    ciphertext = b''
    previous = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        block = pad_pkcs7(block)
        ciphertext_block = encrypt_aes_128_ecb(hex_xor(block, previous), key)
        ciphertext += ciphertext_block
        previous = ciphertext_block
    return ciphertext

def decrypt_aes_128_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 CBC"""
    plaintext = b''
    previous = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = decrypt_aes_128_ecb(block, key)
        plaintext += hex_xor(decrypted_block, previous)
        previous = block
    return plaintext

def encrypt_oracle(plaintext: bytes, mode: str=random.choice(["ECB", "CBC"])) -> bytes:
    """Encrypt plaintext using a random key and AES-128 ECB or CBC mode"""
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = os.urandom(random.randint(5,10)) + plaintext + os.urandom(random.randint(5,10))
    plaintext = pad_pkcs7(plaintext, 16)
    if mode == "ECB":
        return encrypt_aes_128_ecb(plaintext, key)
    elif mode == "CBC":
        return encrypt_aes_128_cbc(plaintext, key, iv)

class ECB_Oracle:
    def __init__(self, append_data: bytes, key: bytes=os.urandom(16)):
        self.key = key
        self.append_data = append_data

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AES-128 ECB"""
        return encrypt_aes_128_ecb(plaintext + self.append_data, self.key)

def find_blocksize(oracle: ECB_Oracle) -> int:
    """Find the blocksize of the oracle"""
    prev_len = len(oracle.encrypt(b''))
    for i in range(1, 256):
        plaintext = b'A' * i
        new_len = len(oracle.encrypt(plaintext))
        if new_len != prev_len:
            return new_len - prev_len
        prev_len = new_len
    return 0

def break_ecb_byte_by_byte(oracle: ECB_Oracle) -> bytes:
    """Break an AES-128 ECB cipher byte by byte"""
    blocksize = find_blocksize(oracle)
    plaintext = b''
    for i in range(len(oracle.encrypt(b''))):
        block_num = i // blocksize
        block_start = block_num * blocksize
        block_end = (block_num + 1) * blocksize
        block = oracle.encrypt(b'A' * (blocksize - 1 - (i % blocksize)))[block_start:block_end]
        for j in range(256):
            test_block = oracle.encrypt(b'A' * (blocksize - 1 - (i % blocksize)) + plaintext + bytes([j]))[block_start:block_end]
            if test_block == block:
                plaintext += bytes([j])
                break
    return plaintext

class Profile_Manager:
    def __init__(self):
        self.key = os.urandom(16)

    @staticmethod
    def structured_cookie_data(data: bytes) -> bytes:
        """Parse and structure cookie data"""
        data = data.decode().split('&')
        data = [d.split('=') for d in data]
        data = dict(data)
        return data

    @staticmethod
    def profile_for(email: bytes) -> bytes:
        """Create a user profile for an email"""
        return b'email=' + email + b'&uid=10&role=user'

    def encrypt_profile(self, email: bytes) -> bytes:
        """Get the encrypted profile for an email"""
        return encrypt_aes_128_ecb(self.profile_for(email), self.key)

    def decrypt_profile(self, ciphertext: bytes) -> bytes:
        """Decrypt a user profile"""
        return self.structured_cookie_data(decrypt_aes_128_ecb(ciphertext, self.key))

class Oracle_14:
    def __init__(self, target_bytes: bytes):
        self.key = os.urandom(16)
        self.random_prefix = os.urandom(random.randint(5,10))
        self.target_bytes = target_bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AES-128 ECB"""
        return encrypt_aes_128_ecb(self.random_prefix + plaintext + self.target_bytes, self.key)

def get_next_byte(prefix_length: int, block_size: int, oracle: Oracle_14, plaintext: bytes) -> bytes:
    """Get the next byte of the target bytes"""
    length = (block_size - prefix_length - (1 + len(plaintext))) % block_size
    dummy_input = b'A' * length
    crack_length = prefix_length + length + len(plaintext) + 1
    real_cipher = oracle.encrypt(dummy_input)
    for j in range(256):
        fake_cipher = oracle.encrypt(dummy_input + plaintext + bytes([j]))
        if fake_cipher[:crack_length] == real_cipher[:crack_length]:
            return bytes([j])
    return b''

def has_equal_blocks(ciphertext: bytes, block_size: int) -> bool:
    """Check if a ciphertext has equal blocks"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    num_dupes =  len(blocks) - len(set(blocks))
    return bool(num_dupes)

def find_prefix_length(oracle: Oracle_14, block_size: int) -> int:
    """Find the length of the random prefix"""
    for i in range(block_size):
        plaintext = b'A' * (block_size * 2 + i)
        ciphertext = oracle.encrypt(plaintext)
        for j in range(0, len(ciphertext) - block_size, block_size):
            if ciphertext[j:j+block_size] == ciphertext[j+block_size:j+block_size*2]:
                return j - i
    return 0

def break_ecb_byte_by_byte_14(oracle: Oracle_14) -> bytes:
    """Break an AES-128 ECB cipher byte by byte"""
    block_size = find_blocksize(oracle)
    prefix_length = find_prefix_length(oracle, block_size)
    unknown_bytes = len(oracle.encrypt(b'')) - prefix_length
    plaintext = b''
    for i in range(unknown_bytes):
        plaintext += get_next_byte(prefix_length, block_size, oracle, plaintext)
    return plaintext


    # def find_block_size(self) -> int:
    #     """Find the block size of the oracle"""
    #     prev_len = len(self.encrypt(b''))
    #     for i in range(1, 256):
    #         plaintext = b'A' * i
    #         new_len = len(self.encrypt(plaintext))
    #         if new_len != prev_len:
    #             self.vaules = prev_len-i
    #             return new_len - prev_len
    #         prev_len = new_len
    #     return 0

    # def find_prefix_length(self) -> int:
    #     """Find the length of the random prefix"""
    #     for i in range(self.block_size):
    #         plaintext = b'A' * (self.block_size * 2 + i)
    #         ciphertext = self.encrypt(plaintext)
    #         for j in range(0, len(ciphertext) - self.block_size, self.block_size):
    #             if ciphertext[j:j+self.block_size] == ciphertext[j+self.block_size:j+self.block_size*2]:
    #                 return j - i
    #     return 0

    # def target_size(self) -> int:
    #     """Find the size of the target bytes"""
    #     return self.vaules - self.prefix_length
    
    # def decrypt(self) -> bytes:
    #     """Decrypt the target bytes"""
    #     plaintext = b''
    #     for i in range(self.target_size()):
    #         block_num = i // self.block_size
    #         block_start = block_num * self.block_size
    #         block_end = (block_num + 1) * self.block_size
    #         block = self.encrypt(b'A' * (self.block_size - 1 - (i % self.block_size)))[block_start:block_end]
    #         for j in range(256):
    #             test_block = self.encrypt(b'A' * (self.block_size - 1 - (i % self.block_size)) + plaintext + bytes([j]))[block_start:block_end]
    #             if test_block == block:
    #                 plaintext += bytes([j])
    #                 break
    #     return plaintext