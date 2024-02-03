
import base64

# Create a function that converts a hex string to base64
def hex_to_base64(hex_string: str) -> str:
    """Convert a hex string to base64"""
    return base64.b64encode(bytes.fromhex(hex_string)).decode("utf-8")

# Write a function that takes two equal-length buffers and produces their XOR combination
def fixed_xor(buffer1: bytes, buffer2: bytes) -> bytes:
    """Produce the XOR combination of two equal-length buffers"""
    output = b""
    for byte1, byte2 in zip(buffer1, buffer2):
        output += bytes(byte1 ^ byte2)

    print(output)
    return output