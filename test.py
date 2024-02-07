# -*- coding: utf-8 -*-

import cryptopals
import pytest

import binascii
import os
import random
import base64

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
    assert cryptopals.break_single_byte_xor(ciphertext)['message'] == b"Cooking MC's like a pound of bacon"

def test_detect_single_char_xor():
    """Test the detect single char xor function"""
    filename = "4.txt"
    assert cryptopals.detect_single_char_xor(filename) == b"Now that the party is jumping\n"

def test_repeating_key_xor():
    """Test the break repeating key xor function"""
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    assert cryptopals.repeating_key_xor(plaintext, key) == b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

def test_break_repeating_key_xor():
    """Test the break repeating key xor function"""
    filename = "6.txt"
    assert cryptopals.break_repeating_key_xor(filename)[1] == b"Terminator X: Bring the noise"

def test_break_aes_128_ecb():
    """Test the break aes 128 ecb function"""
    filename = "7.txt"
    assert cryptopals.break_aes_128_ecb(filename)[:50] == b"I'm back and I'm ringin' the bell \nA rockin' on th"

def test_detect_aes_128_ecb():
    """Test the detect aes 128 ecb function"""
    filename = "8.txt"
    assert cryptopals.detect_aes_128_ecb(filename) == True

def test_pkcs7_padding():
    """Test the pkcs7 padding function"""
    assert cryptopals.pad_pkcs7(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"

def test_cbc_mode():
    """Test the cbc mode function"""
    # Test ecb mode first
    msg = os.urandom(16)
    key = os.urandom(16)
    ciphertext = cryptopals.encrypt_aes_128_ecb(msg, key)
    plaintext = cryptopals.decrypt_aes_128_ecb(ciphertext, key)
    assert plaintext == msg

    # Test cbc mode
    # msg = open("10.txt").read().encode()
    # key = b"YELLOW SUBMARINE"
    # iv = b"\x00" * 16
    msg = os.urandom(16)
    key = os.urandom(16)
    iv = os.urandom(16)
    ciphertext = cryptopals.encrypt_aes_128_cbc(msg, key, iv)
    plaintext = cryptopals.decrypt_aes_128_cbc(ciphertext, key, iv)
    assert plaintext == msg

def test_encrypt_oracle():
    """Test the encrypt oracle function"""
    mode = random.choice(["ECB", "CBC"])
    msg = (b'A'* 50) + os.urandom(50)
    ciphertext = [cryptopals.encrypt_oracle(msg, mode)]
    detected_mode = "ECB" if cryptopals.test_ecb_128(ciphertext) else "CBC"
    assert detected_mode == mode

def test_ecb_oracle():
    """Test the ecb oracle function"""
    DATA_TO_APPEND = base64.b64decode(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    oracle = cryptopals.ECB_Oracle(append_data=DATA_TO_APPEND)
    block_size = cryptopals.find_blocksize(oracle)
    assert block_size == 16
    assert cryptopals.test_ecb_128([oracle.encrypt(b'A'*64)])
    assert cryptopals.break_ecb_byte_by_byte(oracle) == DATA_TO_APPEND + b"\x01"

def test_ecb_cut_paste():
    """Test the ecb cut paste function"""
    manager = cryptopals.Profile_Manager()
    assert manager.profile_for(b"email@example.com") == b'email=email@example.com&uid=10&role=user'
    assert manager.structured_cookie_data(b'email=email@example.com&uid=10&role=user') == {'email': 'email@example.com', 'role': 'user', 'uid': '10'}
    encrypted_profile = manager.encrypt_profile(b'email@example.com')
    assert manager.decrypt_profile(encrypted_profile) == {'email': 'email@example.com', 'role': 'user', 'uid': '10'}

    block_size = 16
    target_email = b"eeeeeeeeeeeemail@attacker.com"

    ciphertext = manager.encrypt_profile(target_email)
    plaintext = cryptopals.pad_pkcs7(b"admin", 16)
    payload_email = b"nextBlockShouldSt@rt.Here:" + plaintext

    ciphertext_t = manager.encrypt_profile(payload_email)
    block = ciphertext_t[2*block_size:3*block_size]
    crafted_ciphertext = ciphertext[:-block_size] + block
    profile = manager.decrypt_profile(crafted_ciphertext)
    assert profile['role'] == 'admin'

def test_oracle_14():
    """Test the oracle 14 function"""
    ciphertext = base64.b64decode(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    oracle = cryptopals.Oracle_14(target_bytes=ciphertext)
    assert cryptopals.break_ecb_byte_by_byte_14(oracle) == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"
    # assert cryptopals.break_ecb_byte_by_byte(oracle) == oracle.append_data + b"\x01"