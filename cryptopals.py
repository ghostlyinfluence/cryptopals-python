
import binascii
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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