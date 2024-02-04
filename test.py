# create test using pytest to test a hex to base64 function

import cryptopals
import pytest

import binascii

def test_hex_to_base64():
    """Test the hex_to_base64 function"""
    assert cryptopals.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" 

def test_hex_xor():
    """Test the fixed_xor function"""
    a = binascii.unhexlify('1c0111001f010100061a024b53535009181c')
    b = binascii.unhexlify('686974207468652062756c6c277320657965')
    expected_result = binascii.unhexlify('746865206b696420646f6e277420706c6179')
    assert cryptopals.hex_xor(a,b) == expected_result

def test_single_hex_xor():
    """Test the single byte xor function"""
    ciphertext = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    assert cryptopals.break_single_byte_xor(ciphertext) == b"Cooking MC's like a pound of bacon"

def test_detect_single_char_xor():
    """Test the detect single char xor function"""
    filename = "4.txt"
    assert cryptopals.detect_single_char_xor(filename) == b"Now that the party is jumping\n"