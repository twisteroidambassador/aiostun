# aiostun

STUN (STUNbis, RFC 5389) protocol support on Python 3 asyncio. Supports Python 3.5 and newer.

This is a work in progress. Features supported so far:

* Building and parsing STUN messages
  - Supports all attributes specified in RFC 5389
* Sending and receiving STUN messages over UDP
  - Tracks responses: simply send a request and `await` the response
  - Automatically retransmits requests and handles RTO
* Supports authentication: both long-term and short-term credentials

Todo:

* Some examples.
* ICE support.
* TURN support.
