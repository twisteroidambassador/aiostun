"""Encoding and decoding of STUN messages."""

# import random
import os
import enum
import binascii
import hmac
import hashlib
import ipaddress
import struct
from collections import namedtuple
from functools import partial

from .utils import (saslprep, xor_bytes, bit_mask, get_enum)
from .exceptions import (STUNMessageParseError,
                         InvalidSTUNMessage,
                         MissingSTUNAttribute,
                         STUNAttributeParseError,
                         )

# sr = random.SystemRandom()

ParsedAttribute = namedtuple('ParsedAttribute',
                             ['attr_type', 'data', 'begin', 'end'])
BuiltAttribute = namedtuple('BuiltAttribute', ['attr_type', 'data'])


class STUNMethod(enum.IntEnum):
    """The method field in STUN header.
    
    References:
    https://tools.ietf.org/html/rfc5389#section-18.1
    https://tools.ietf.org/html/rfc5766#section-13
    """
    # STUN
    BINDING = 0x001
    # TURN
    ALLOCATE = 0x003
    REFRESH = 0x004
    SEND = 0x006
    DATA = 0x007
    CREATE_PERMISSION = 0x008
    CHANNEL_BIND = 0x009


class STUNClass(enum.IntEnum):
    """The class field in STUN header.
    
    References:
    https://tools.ietf.org/html/rfc5389#section-6
    """
    REQUEST = 0b00
    INDICATION = 0b01
    SUCCESS_RESPONSE = 0b10
    ERROR_RESPONSE = 0b11


class STUNAttribute(enum.IntEnum):
    """STUN attribute types.
    
    References:
    https://tools.ietf.org/html/rfc5389#section-18.2
    https://tools.ietf.org/html/rfc5766#section-14
    https://tools.ietf.org/html/rfc5245#section-21.2
    https://tools.ietf.org/html/rfc5780#section-7
    """
    # STUN
    MAPPED_ADDRESS = 0x0001
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    ERROR_CODE = 0x0009
    UNKNOWN_ATTRIBUTES = 0x000A
    REALM = 0x0014
    NONCE = 0x0015
    XOR_MAPPED_ADDRESS = 0x0020
    SOFTWARE = 0x8022
    ALTERNATE_SERVER = 0x8023
    FINGERPRINT = 0x8028
    # STUN - Reserved
    RESERVED = 0x0000
    RESERVED_RESPONSE_ADDRESS = 0x0002
    RESERVED_SOURCE_ADDRESS = 0x0004
    RESERVED_CHANGED_ADDRESS = 0x0005
    RESERVED_PASSWORD = 0x0007
    RESERVED_REFLECTED_FROM = 0x000B
    # TURN
    CHANNEL_NUMBER = 0x000C
    LIFETIME = 0x000D
    XOR_PEER_ADDRESS = 0x0012
    DATA = 0x0013
    XOR_RELAYED_ADDRESS = 0x0016
    EVEN_PORT = 0x0018
    REQUESTED_TRANSPORT = 0x0019
    DONT_FRAGMENT = 0x001A
    RESERVATION_TOKEN = 0x0022
    # ICE
    PRIORITY = 0x0024
    USE_CANDIDATE = 0x0025
    ICE_CONTROLLED = 0x8029
    ICE_CONTROLLING = 0x802A
    # NAT Behavior Discovery using STUN
    CHANGE_REQUEST = 0x0003
    PADDING = 0x0026
    RESPONSE_PORT = 0x0027
    RESPONSE_ORIGIN = 0x802B
    OTHER_ADDRESS = 0x802C


class STUNError(enum.IntEnum):
    """STUN error code, used in error response messages.
    
    References:
    https://tools.ietf.org/html/rfc5389#section-15.6
    https://tools.ietf.org/html/rfc5766#section-15
    https://tools.ietf.org/html/rfc5245#section-21.3
    """
    # STUN
    TRY_ALTERNATE = 300
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    UNKNOWN_ATTRIBUTE = 420
    STALE_NONCE = 438
    SERVER_ERROR = 500
    # TURN
    FORBIDDEN = 403
    ALLOCATION_MISMATCH = 437
    WRONG_CREDENTIALS = 441
    UNSUPPORTED_TRANSPORT_PROTOCOL = 442
    ALLOCATION_QUOTA_REACHED = 486
    INSUFFICIENT_CAPACITY = 508
    # ICE
    ROLE_CONFLICT = 487


class STUNAddressFamily(enum.IntEnum):
    IPV4 = 0x01
    IPV6 = 0x02


request_response = {
    STUNClass.REQUEST,
    STUNClass.SUCCESS_RESPONSE,
    STUNClass.ERROR_RESPONSE,
}
indication_only = {STUNClass.INDICATION}
ALLOWED_CLASS_FOR_METHOD = {
    STUNMethod.ALLOCATE: request_response,
    STUNMethod.REFRESH: request_response,
    STUNMethod.SEND: indication_only,
    STUNMethod.DATA: indication_only,
    STUNMethod.CREATE_PERMISSION: request_response,
    STUNMethod.CHANNEL_BIND: request_response,
}


def random_trans_id():
    """Generate a random 96-bit Transaction ID."""
    return os.urandom(12)


def key_from_long_term_cred(username, realm, password):
    """Calculate the 16-byte key from long-term credentials.
    
    Arguments:
    username, realm, password: the long-term credentials used to derive the key.
        username should have been processed with SASLPrep already. All 3
        arguments should not have quotes or trailing nulls.
    """
    creds = b':'.join([username.encode('utf-8'),
                       realm.encode('utf-8'),
                       saslprep(password).encode('utf-8')])
    return hashlib.md5(creds).digest()


def key_from_short_term_cred(password):
    """Calculate the key from short-term credentials."""
    return saslprep(password).encode('utf-8')


class STUNMessage:
    """Base class for STUN message builder / parser.
    
    Includes common methods and constants.
    """
    HEADER_LEN = 20
    MAGIC_COOKIE = b'\x21\x12\xA4\x42'
    FINGERPRINT_XOR = 0x5354554e


class STUNMessageParser(STUNMessage):
    """Parse a STUN message.

    Usage:
    Create a new instance with the message data as argument. This will parse the
    structure of the message. Call check_integrity() if required. Then call any
    of the parse_ATTRIBUTE_NAME methods to parse the contents of the attributes.
    """

    def __init__(self, data, *,
                 allowed_class_for_method=ALLOWED_CLASS_FOR_METHOD):
        self.data = data
        self._allowed_class_for_method = allowed_class_for_method

        self._parse_message_structure()

    def _parse_message_structure(self):
        """Parse self.data as a STUN message, stage 1.
        
        Checks the header makes sense, extract attributes into self.attr, and 
        check the fingerprint if there is one.
        
        Output: sets these attributes on self:
        self.length: the Length field in header.
        self.method: the STUN Method. An instance of STUNMethod.
        self.class_: the STUN Class. An instance of STUNClass.
        self.trans_id: the 96-bit Transaction ID. Bytes.
        self.has_fingerprint: whether the message contains a valid FINGERPRINT
            attribute.
        self.has_message_integrity: whether the message contains a
            MESSAGE-INTEGRITY attribute. Note: its validity is not yet verified.
        self.attr: list of attributes in the message. Each item in list is a 
            namedtuple STUNAttributeData(attr_type, data, begin, end).
            attr_type: the Attribute Type. An instance of STUNAttribute if the 
                attribute is known, otherwise an int.
            data: the payload data of the attribute. Alignment padding is
                already stripped.
            begin, end: byte indices of the beginning and end of this attribute
                record in self.data.
        
        Exceptions:
        InvalidSTUNMessage: raised when the message is not a well-formed STUN
            message. The message should be silently discarded.
        
        References:
        https://tools.ietf.org/html/rfc5389#section-6
        https://tools.ietf.org/html/rfc5389#section-7.3
        """
        # ========== Parse header ==========
        data_len = len(self.data)
        if data_len < self.HEADER_LEN:
            raise InvalidSTUNMessage('Message shorter than HEADER_LEN')
        if self.data[0] & bit_mask(2, 6):
            raise InvalidSTUNMessage('Most significant 2 bits not zero')
        type_, self.length, cookie, self.trans_id = struct.unpack_from(
            '!HH4s12s', self.data, 0)
        if cookie != self.MAGIC_COOKIE:
            raise InvalidSTUNMessage('Magic cookie value incorrect')
        if self.length % 4:
            raise InvalidSTUNMessage('Length field {} not multiple of 4'
                                     .format(self.length))
        if self.length + self.HEADER_LEN != data_len:
            raise InvalidSTUNMessage('Length field incorrect')
        method = ((type_ & bit_mask(4))
                  | ((type_ & bit_mask(3, 5)) >> 1)
                  | ((type_ & bit_mask(5, 9)) >> 2))
        class_ = (((type_ & bit_mask(1, 4)) >> 4)
                  | ((type_ & bit_mask(1, 8)) >> 7))
        try:
            self.method = STUNMethod(method)
        except ValueError:
            raise InvalidSTUNMessage('Unknown method 0x{:03X}'.format(method))
        self.class_ = STUNClass(class_)
        if (self.method in self._allowed_class_for_method and
                self.class_ not in self._allowed_class_for_method[self.method]):
            raise InvalidSTUNMessage('STUN method {!r} does not allow '
                                     'class {!r}'.format(self.method,
                                                         self.class_))
        # ========== Parse attributes ==========
        self.attr = []
        end = self.HEADER_LEN
        while end < data_len:
            begin = end
            attr_type, attr_len = struct.unpack_from('!HH', self.data, begin)
            attr_type = get_enum(STUNAttribute, attr_type)
            end = begin + 4 + ((attr_len - 1) // 4 + 1) * 4
            attr_data = self.data[begin + 4: begin + 4 + attr_len]
            self.attr.append(ParsedAttribute(
                attr_type, attr_data, begin, end))
        # ========== Check fingerprint ==========
        self.has_fingerprint = False
        self.has_message_integrity = False
        if not self.attr:  # no attributes; header-only message
            return
        if any(attr.attr_type == STUNAttribute.FINGERPRINT
               for attr in self.attr[:-1]):
            raise InvalidSTUNMessage(
                'Fingerprint attribute not in last position')
        if self.attr[-1].attr_type == STUNAttribute.FINGERPRINT:
            self.has_fingerprint = True
            crc_data = self.data[:self.attr[-1].begin]
            crc32 = binascii.crc32(crc_data)
            if ((crc32 ^ self.FINGERPRINT_XOR).to_bytes(4, 'big')
                    != self.attr[-1].data):
                raise InvalidSTUNMessage('Fingerprint invalid')
            # del self.attr[-1]
            self.attr = self.attr[:-1]
        # ========== Check existence of message integrity attr ===========
        for idx, attr in enumerate(self.attr):
            if attr.attr_type == STUNAttribute.MESSAGE_INTEGRITY:
                # MUST ignore all other attributes that follow MESSAGE-INTEGRITY
                self.has_message_integrity = True
                self.attr = self.attr[:idx + 1]
                break

    def check_message_integrity(self, key):
        """Verify the MESSAGE-INTEGRITY attribute with the given key.
        
        Returns True if the MESSAGE-INTEGRITY attribute is valid, and False
        otherwise.
        
        Arguments:
        key: the key derived from long-term or short-term credentials.
        
        References:
        https://tools.ietf.org/html/rfc5389#section-15.4
        """
        assert self.has_message_integrity, (
            'check_message_integrity() called '
            'when message does not include MESSAGE-INTEGRITY attribute')
        assert self.attr[-1].attr_type == STUNAttribute.MESSAGE_INTEGRITY, (
            'Last attribute not MESSAGE-INTEGRITY')
        msg_int = self.attr[-1]
        partial_data = bytearray(self.data[:msg_int.begin])
        struct.pack_into('!H', partial_data, 2, msg_int.end - self.HEADER_LEN)
        digest = hmac.new(key, partial_data, 'sha1').digest()
        return hmac.compare_digest(digest, msg_int.data)

    def find_first_attribute(self, attr):
        """Return the first `attr` attribute in the message.
        
        Arguments:
        attr: a STUNAttribute object representing the desired attribute.
        
        Returns:
        A tuple (index, attribute) where attribute is the parsed attribute and 
        index is the index of the attribute in self.attr.
        
        Exceptions:
        MissingSTUNAttribute: raised if there is no `attr` in self.attr.
        """
        for idx, attribute in enumerate(self.attr):
            if attribute.attr_type == attr:
                return idx, attribute
        else:
            raise MissingSTUNAttribute("No {!r} in message".format(attr))

    def _unxor_address(self, data):
        """Parse the payload of an XOR-*-ADDRESS attribute."""
        family = STUNAddressFamily(data[1])
        port = int.from_bytes(xor_bytes(
            data[2:4], self.MAGIC_COOKIE[:2]), 'big')
        if family == STUNAddressFamily.IPV4:
            addr = ipaddress.IPv4Address(xor_bytes(
                data[4:8], self.MAGIC_COOKIE))
        elif family == STUNAddressFamily.IPV6:
            addr = ipaddress.IPv6Address(xor_bytes(
                data[4:20], self.MAGIC_COOKIE + self.trans_id))
        else:
            raise STUNAttributeParseError('Unknown address family')
        return addr, port

    @staticmethod
    def _parse_address(data):
        """Parse the payload of a MAPPED-ADDRESS or similar attribute."""
        family, port = struct.unpack_from('!xBH', data, 0)
        if family == STUNAddressFamily.IPV4:
            address = ipaddress.IPv4Address(data[4:8])
        elif family == STUNAddressFamily.IPV6:
            address = ipaddress.IPv6Address(data[4:20])
        else:
            raise STUNAttributeParseError('Unknown address family')
        return address, port

    def parse_xor_mapped_address(self):
        """Parse the first XOR-MAPPED-ADDRESS attribute.
        
        Returns (address, port).
        address: an ipaddress.IPv4Address or IPv6Address object.
        port: the port number.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.2
        """
        _, attr = self.find_first_attribute(STUNAttribute.XOR_MAPPED_ADDRESS)
        return self._unxor_address(attr.data)

    def parse_mapped_address(self):
        """Parse the first MAPPED-ADDRESS attribute."""
        _, attr = self.find_first_attribute(STUNAttribute.MAPPED_ADDRESS)
        return self._parse_address(attr.data)

    def parse_username(self):
        """Parse the first USERNAME attribute.
        
        Returns username as a string.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.3
        """
        _, attr = self.find_first_attribute(STUNAttribute.USERNAME)
        return attr.data.decode('utf-8')

    def parse_error_code(self):
        """Parse the first ERROR-CODE attribute.
        
        Returns (error_code, reason).
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.6
        """
        _, attr = self.find_first_attribute(STUNAttribute.ERROR_CODE)
        error_class, error_number = struct.unpack_from('!2xBB', attr.data, 0)
        if error_class < 3 or error_class > 6:
            raise STUNAttributeParseError('Hundreds digit of error code not '
                                          'between 3 and 6')
        if error_number > 99:
            raise STUNAttributeParseError('Lower 2 digits of error code larger'
                                          'than 99')
        error_code = get_enum(STUNError, error_class * 100 + error_number)
        reason = attr.data[4:].decode('utf-8')
        return error_code, reason

    def parse_realm(self):
        """Parse the first REALM attribute.
        
        Returns realm as a string.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.7
        """
        _, attr = self.find_first_attribute(STUNAttribute.REALM)
        return attr.data.decode('utf-8')

    def parse_nonce(self):
        """Parse the first NONCE attribute.
        
        Returns nonce as a string.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.8
        """
        _, attr = self.find_first_attribute(STUNAttribute.NONCE)
        return attr.data.decode('utf-8')

    def parse_unknown_attributes(self):
        """Parse the first UNKNOWN-ATTRIBUTES attribute.
        
        Returns a list of attribute types.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.9
        """
        _, attr = self.find_first_attribute(STUNAttribute.UNKNOWN_ATTRIBUTES)
        return [get_enum(STUNAttribute, t) for t in
                struct.unpack('!{:d}H'.format(len(attr.data) // 2), attr.data)]

    def parse_software(self):
        """Parse the first SOFTWARE attribute.
        
        Returns software as a string.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.10
        """
        _, attr = self.find_first_attribute(STUNAttribute.SOFTWARE)
        return attr.data.decode('utf-8')

    def parse_alternate_server(self):
        """Parse the first ALTERNATE-SERVER attribute.
        
        Returns (address, port).
        address: an ipaddress.IPv4Address or IPv6Address object.
        port: the port number.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.11
        """
        _, attr = self.find_first_attribute(STUNAttribute.ALTERNATE_SERVER)
        return self._parse_address(attr.data)


class STUNMessageBuilder(STUNMessage):
    """Build a STUN message.

    Usage: Create a new instance, set method and class, set key and
    want_fingerprint if desired, set trans_id if a random one won't do. Call
    any of the build_ATTRIBUTE_NAME methods to add attributes. Then call
    build() to build the message. If a transaction ID is not given, a random
    one will be assigned during build().
    """
    EXTRA_LENGTH_MESSAGE_INTEGRITY = 4 + 20
    EXTRA_LENGTH_FINGERPRINT = 4 + 4

    def __init__(self, method=None, class_=None, trans_id=None, key=None,
                 want_fingerprint=False):
        self.method = method
        self.class_ = class_
        self.trans_id = trans_id
        self.key = key
        self.want_fingerprint = want_fingerprint
        self.attr = []
        self.data = None

    @staticmethod
    def _build_attr_data(attr):
        """Build a STUN attribute record from the given BuiltAttribute
        namedtuple.
        """
        if callable(attr.data):
            data = attr.data()
        else:
            data = attr.data
        attr_len = len(data)
        padded_len = ((attr_len - 1) // 4 + 1) * 4
        return struct.pack('!HH{:d}s'.format(padded_len),
                           attr.attr_type, attr_len, data)

    def _patch_header_length(self, data, extra_length):
        """Modify the length in the message header."""
        struct.pack_into('!H', data, 2,
                         len(data) + extra_length - self.HEADER_LEN)

    def build(self):
        """Assemble the STUN message, store it in self.data and return it.
        
        Inputs:
        self.trans_id
        self.key
        self.want_fingerprint
        self.attr
        """

        assert self.method is not None, 'No STUN method set'
        assert self.class_ is not None, 'No STUN class set'
        if self.trans_id is None:
            self.trans_id = random_trans_id()
        type_ = ((self.method & bit_mask(4))
                 | (self.method & bit_mask(3, 4)) << 1
                 | (self.method & bit_mask(5, 7)) << 2
                 | (self.class_ & bit_mask(1)) << 4
                 | (self.class_ & bit_mask(1, 1)) << 7)
        partial_data = bytearray(self.HEADER_LEN)
        struct.pack_into('!H2x4s12s', partial_data, 0,
                         type_, self.MAGIC_COOKIE, self.trans_id)
        for attr in self.attr:
            partial_data.extend(self._build_attr_data(attr))
        if self.key is not None:
            self._patch_header_length(partial_data,
                                      self.EXTRA_LENGTH_MESSAGE_INTEGRITY)
            hmacsha1 = hmac.new(self.key, partial_data, 'sha1').digest()
            msg_int = ParsedAttribute(STUNAttribute.MESSAGE_INTEGRITY,
                                      hmacsha1, None, None)
            partial_data.extend(self._build_attr_data(msg_int))
        if self.want_fingerprint:
            self._patch_header_length(partial_data,
                                      self.EXTRA_LENGTH_FINGERPRINT)
            crc32 = binascii.crc32(partial_data)
            fingerprint = ParsedAttribute(
                STUNAttribute.FINGERPRINT,
                (crc32 ^ self.FINGERPRINT_XOR).to_bytes(4, 'big'),
                None, None)
            partial_data.extend(self._build_attr_data(fingerprint))
        self._patch_header_length(partial_data, 0)
        self.data = partial_data
        return partial_data

    def _build_attribute(self, attr_type, data):
        """Add an attribute."""
        self.attr.append(BuiltAttribute(attr_type, data))

    def build_xor_mapped_address(self, address, port):
        """Add an XOR-MAPPED-ADDRESS attribute.
        
        Arguments:
        address: an ipaddress.IPv4Address or ipaddress.IPv6Address object.
        port: port number.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.2
        """
        self._build_attribute(STUNAttribute.XOR_MAPPED_ADDRESS,
                              partial(self._xor_address, address, port))

    def build_mapped_address(self, address, port):
        """Add a MAPPED-ADDRESS attribute."""
        self._build_attribute(STUNAttribute.MAPPED_ADDRESS,
                              partial(self._make_address, address, port))

    def _xor_address(self, address, port):
        x_port = xor_bytes(port.to_bytes(2, 'big'), self.MAGIC_COOKIE[:2])
        if address.version == 4:
            family = STUNAddressFamily.IPV4
            x_addr = xor_bytes(address.packed, self.MAGIC_COOKIE)
            struct_format = '!xB2s4s'
        elif address.version == 6:
            family = STUNAddressFamily.IPV6
            x_addr = xor_bytes(address.packed,
                               self.MAGIC_COOKIE + self.trans_id)
            struct_format = '!xB2s16s'
        return struct.pack(struct_format, family, x_port, x_addr)

    @staticmethod
    def _make_address(address, port):
        if address.version == 4:
            family = STUNAddressFamily.IPV4
            struct_format = '!xBH4s'
        elif address.version == 6:
            family = STUNAddressFamily.IPV6
            struct_format = '!xBH16s'
        return struct.pack(struct_format, family, port, address.packed)

    def build_username(self, username):
        """Add an USERNAME attribute.
        
        Arguments:
        username: a string denoting the username. Will be processed by SASLprep.
            The prepped and encoded string must be shorter than 513 bytes.
        
        Returns username processed by SASLprep, which can then be used for e.g.
        building a key used in MESSAGE-INTEGRITY.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.3
        """
        username = saslprep(username)
        username_b = username.encode('utf-8')
        if len(username_b) > 512:
            raise ValueError('SASLprepped and encoded username too long')
        self._build_attribute(STUNAttribute.USERNAME, username_b)
        return username

    def build_error_code(self, error, reason=None):
        """Add an ERROR-CODE attribute.
        
        Arguments:
        error: an instance of STUNError. The error code.
        reason: a reason phrase. Must be less than 128 characters. Defaults to
            the name of the error.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.6
        """
        if reason is None:
            try:
                reason = error.name.replace('_', ' ').title()
            except AttributeError:
                reason = 'Unknown Error'
        if len(reason) >= 128:
            raise ValueError('Reason phrase too long')
        error_class, error_number = divmod(error, 100)
        if error_class < 3 or error_class > 6:
            raise ValueError('Hundreds digit of error code not between 3 and 6')
        data = bytes([0, 0, error_class, error_number]) + reason.encode('utf-8')
        self._build_attribute(STUNAttribute.ERROR_CODE, data)

    def build_realm(self, realm):
        """Add a REALM attribute.
        
        Arguments:
        realm: the realm string. Must be less than 128 characters. It should 
            be a sequence of qdtext or quoted-pair, but this is not checked.
            Will be processed by SASLprep.
        
        Returns realm, after being processed by SASLprep.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.7
        """
        realm = saslprep(realm)
        if len(realm) >= 128:
            raise ValueError('Realm value too long')
        self._build_attribute(STUNAttribute.REALM, realm.encode('utf-8'))
        return realm

    def build_nonce(self, nonce):
        """Add a NONCE attribute.
        
        Arguments:
        realm: the realm string. Must be less than 128 characters. It should 
            be a sequence of qdtext or quoted-pair, but this is not checked.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.8
        """
        if len(nonce) >= 128:
            raise ValueError('Nonce value too long')
        self._build_attribute(STUNAttribute.NONCE, nonce.encode('utf-8'))

    def build_unknown_attributes(self, attributes):
        """Add an UNKNOWN-ATTRIBUTES attribute.
        
        Arguments:
        attributes: a sequence of attribute types.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.9
        """
        data = struct.pack('!{:d}H'.format(len(attributes)), *attributes)
        self._build_attribute(STUNAttribute.UNKNOWN_ATTRIBUTES, data)

    def build_software(self, software):
        """Add a SOFTWARE attribute.
        
        Arguments:
        software: a string describing software name and version.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.10
        """
        if len(software) >= 128:
            raise ValueError('Software string too long')
        self._build_attribute(STUNAttribute.SOFTWARE, software.encode('utf-8'))

    def build_alternate_server(self, address, port):
        """Add an ALTERNATE-SERVER attribute.
        
        address: an ipaddress.IPv4Address or ipaddress.IPv6Address object.
        port: port number.
        
        Reference:
        https://tools.ietf.org/html/rfc5389#section-15.11
        """
        self._build_attribute(STUNAttribute.ALTERNATE_SERVER,
                              self._make_address(address, port))
