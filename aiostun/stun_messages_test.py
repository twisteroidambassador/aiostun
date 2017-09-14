import pytest
import random
import ipaddress
import string

from . import stun_messages

# Test vectors from:
# https://tools.ietf.org/html/rfc5769

# req_ipv4 = bytes.fromhex('000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf')

req_ipv4 = (b"\x00\x01\x00\x58"
            b"\x21\x12\xa4\x42"
            b"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
            b"\x80\x22\x00\x10"
            b"STUN test client"
            b"\x00\x24\x00\x04"
            b"\x6e\x00\x01\xff"
            b"\x80\x29\x00\x08"
            b"\x93\x2f\xf9\xb1\x51\x26\x3b\x36"
            b"\x00\x06\x00\x09"
            b"\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20"
            b"\x00\x08\x00\x14"
            b"\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5"
            b"\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2"
            b"\x80\x28\x00\x04"
            b"\xe5\x7a\x3b\xcf")

req_ltc = (b"\x00\x01\x00\x60"
           b"\x21\x12\xa4\x42"
           b"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"
           b"\x00\x06\x00\x12"
           b"\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83"
           b"\xe3\x82\xaf\xe3\x82\xb9\x00\x00"
           b"\x00\x15\x00\x1c"
           b"\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36"
           b"\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79"
           b"\x36\x34\x73\x41"
           b"\x00\x14\x00\x0b"
           b"\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00"
           b"\x00\x08\x00\x14"
           b"\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71"
           b"\x2e\x85\xc9\xa2\x8c\xa8\x96\x66")


def test_stunmessage_parse_req_ipv4():
    software = 'STUN test client'
    username = 'evtj:h6vY'
    password = 'VOkJxbRl1RmTxUk/WvJxBt'

    sm = stun_messages.STUNMessageParser(req_ipv4)
    assert sm.method == stun_messages.STUNMethod.BINDING
    assert sm.class_ == stun_messages.STUNClass.REQUEST
    assert sm.has_fingerprint
    assert sm.has_message_integrity
    key = stun_messages.key_from_short_term_cred(password)
    assert sm.check_message_integrity(key)
    assert sm.parse_username() == username
    assert sm.parse_software() == software


def test_stunmessage_parse_ltc():
    username = '\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9'
    password = 'The\u00ADM\u00AAtr\u2168'
    nonce = 'f//499k954d6OL34oL9FSTvy64sA'
    realm = 'example.org'

    sm = stun_messages.STUNMessageParser(req_ltc)
    assert sm.method == stun_messages.STUNMethod.BINDING
    assert sm.class_ == stun_messages.STUNClass.REQUEST
    assert not sm.has_fingerprint
    assert sm.has_message_integrity
    key = stun_messages.key_from_long_term_cred(username, realm, password)
    assert sm.check_message_integrity(key)
    assert sm.parse_username() == username


def build_random_message():
    method = random.choice(list(stun_messages.STUNMethod))
    allowed_class = list(stun_messages.ALLOWED_CLASS_FOR_METHOD.get(
        method,
        stun_messages.STUNClass))
    class_ = random.choice(allowed_class)
    builder = stun_messages.STUNMessageBuilder(method, class_)
    return builder


def random_string(length):
    pool = string.digits + string.ascii_letters + string.punctuation + ' '
    return ''.join(random.choice(pool) for _ in range(length))


def test_stunmessage_build_parse():
    key = random.getrandbits(16 * 8).to_bytes(16, 'big')
    method = random.choice(list(stun_messages.STUNMethod))
    allowed_class = list(stun_messages.ALLOWED_CLASS_FOR_METHOD.get(
        method,
        stun_messages.STUNClass))
    class_ = random.choice(allowed_class)
    # class_ = random.choice(list(stun_messages.STUNClass))
    builder = stun_messages.STUNMessageBuilder(method, class_)
    builder.key = key
    builder.want_fingerprint = True
    message = builder.build()
    trans_id = builder.trans_id
    parser = stun_messages.STUNMessageParser(message)
    assert parser.method == method
    assert parser.class_ == class_
    assert parser.trans_id == trans_id
    assert parser.check_message_integrity(key)


def test_stunmessage_build_parse_xor_mapped_address():
    builder = build_random_message()
    method = builder.method
    class_ = builder.class_
    random_ip_address = ipaddress.ip_address(
        random.getrandbits(random.choice([4 * 8, 16 * 8])))
    random_port = random.getrandbits(16)
    builder.build_xor_mapped_address(random_ip_address, random_port)
    message = builder.build()
    trans_id = builder.trans_id
    parser = stun_messages.STUNMessageParser(message)
    assert parser.method == method
    assert parser.class_ == class_
    assert parser.trans_id == trans_id
    assert parser.parse_xor_mapped_address() == (random_ip_address, random_port)


def test_stunmessage_build_parse_username_realm():
    builder = build_random_message()
    method = builder.method
    class_ = builder.class_
    username = '你好hello world'
    realm = random_string(random.randrange(10, 127))
    username = builder.build_username(username)
    realm = builder.build_realm(realm)
    message = builder.build()
    trans_id = builder.trans_id
    parser = stun_messages.STUNMessageParser(message)
    assert parser.method == method
    assert parser.class_ == class_
    assert parser.trans_id == trans_id
    assert parser.parse_username() == username
    assert parser.parse_realm() == realm


def test_stunmessage_build_parse_error_code_unknown_attr():
    builder = build_random_message()
    method = builder.method
    class_ = builder.class_
    error_code = stun_messages.STUNError.UNKNOWN_ATTRIBUTE
    unknown_attr = (
    0x8033, 0x8093, 0x80AF, stun_messages.STUNError.UNKNOWN_ATTRIBUTE)
    builder.build_error_code(error_code)
    builder.build_unknown_attributes(unknown_attr)
    message = builder.build()
    trans_id = builder.trans_id
    parser = stun_messages.STUNMessageParser(message)
    assert parser.method == method
    assert parser.class_ == class_
    assert parser.trans_id == trans_id
    assert parser.parse_error_code() == (error_code, 'Unknown Attribute')
    assert all(
        a == b for a, b in zip(parser.parse_unknown_attributes(), unknown_attr))


def test_key_from_long_term_cred():
    key = stun_messages.key_from_long_term_cred('user', 'realm', 'pass')
    assert key == bytes.fromhex('8493fbc53ba582fb4c044c456bdc40eb')
