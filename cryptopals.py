
import binascii
import base64

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

def break_single_byte_xor(ciphertext: bytes) -> str:
    """Break a single-byte XOR cipher"""
    scores = {}
    for i in range(256):
        keystream = bytes([i] * len(ciphertext))
        plaintext = hex_xor(ciphertext, keystream)
        scores[i] = score_text(plaintext)
    key = max(scores, key=scores.get)
    return hex_xor(ciphertext, bytes([key] * len(ciphertext)))

def detect_single_char_xor(filename: str) -> bytes:
    """Detect the single character XOR cipher from a file"""
    candidates = {}
    with open(filename) as data:
        for line in data:
            ciphertext = binascii.unhexlify(line.strip())
            plaintext = break_single_byte_xor(ciphertext)
            candidates[plaintext] = score_text(plaintext)
    best_candidate = max(candidates, key=candidates.get)
    print(best_candidate)
    return best_candidate

def repeating_key_xor(ciphertext: bytes, key: bytes) -> bytes:
    """Break a repeating-key XOR cipher"""
    keystream = key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)]
    return binascii.hexlify(hex_xor(ciphertext, keystream))