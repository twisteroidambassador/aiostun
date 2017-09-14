"""Exceptions used in this package."""


class STUNError:
    """Base class for all exceptions used in this package."""
    pass


class STUNMessageParseError(STUNError):
    """Errors during STUN message parsing."""
    pass


class InvalidSTUNMessage(STUNMessageParseError, ValueError):
    """The packet is not a well-formed STUN message.
    
    In cases where STUN is multiplexed with other packets, this may mean the
    packet is not STUN but the other multiplexed protocol.
    
    References:
    https://tools.ietf.org/html/rfc5389#section-7.3
    """
    pass


class MissingSTUNAttribute(STUNMessageParseError, LookupError):
    """An expected attribute is missing in the message."""
    pass


class STUNAttributeParseError(STUNMessageParseError, ValueError):
    """Error while parsing a STUN attribute. 
    
    The attribute does not conform to the specifications in the various RFCs.
    """
    pass

class STUNTransactionTimeout(STUNError, TimeoutError):
    """STUN transaction timed out.

    All resend attempts are exhausted, and after a final timeout, no response
    was received.
    """
    pass
