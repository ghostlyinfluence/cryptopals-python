
import base64
import bytes

# Create a function that converts a hex string to base64
def hex_to_base64(hex_string: str) -> str:
    """Convert a hex string to base64"""
    return base64.b64encode(bytes.fromhex(hex_string)).decode("utf-8")

# Write a function that takes two equal-length buffers and produces their XOR combination
def hex_xor(buffer1: str, buffer2: str) -> str:
    """Produce the XOR combination of two equal-length buffers"""
    buf1 = int(buffer1, 16)
    buf2 = int(buffer2, 16)
    xor = buf1 ^ buf2
    return hex(xor)[2:]

# Create a dictionary containing letters of the alphabet and their corresponding frequency in the English language
letter_freq = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702, "f": 0.02228,
    "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153, "k": 0.00772, "l": 0.04025,
    "m": 0.02406, "n": 0.06749, "o": 0.07507, "p": 0.01929, "q": 0.00095, "r": 0.05987,
    "s": 0.06327, "t": 0.09056, "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150,
    "y": 0.01974, "z": 0.00074
}

def score_text(text: str) -> float:
    """Score the text based on the frequency of English letters"""
    score = 0
    for char in text:
        if char.lower() in letter_freq:
            score += letter_freq[char.lower()]
    return score

def break_single_byte_xor(ciphertext: str) -> str:
    """Break a single-byte XOR cipher"""
    scores = {}
    for key in letter_freq:
        plaintext = ""
        for char in ciphertext:
            plaintext += hex_to_base64(hex_xor(char, key)
        scores[key] = score_text(plaintext)
    return max(scores, key=scores.get)