# create test using pytest to test a hex to base64 function

import cryptopals
import pytest

def test_hex_to_base64():
    """Test the hex_to_base64 function"""
    assert cryptopals.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" 

def test_fixed_xor():
    """Test the fixed_xor function"""
    assert cryptopals.fixed_xor(b"1c0111001f010100061a024b53535009181c", b"686974207468652062756c6c277320657965") == b"746865206b696420646f6e277420706c6179"