# aiostun

STUN (STUNbis, RFC 5389) protocol support on Python 3 asyncio. Supports Python 3.5 and newer. No external dependencies (yet).

This is a work in progress. Features supported so far:

* Building and parsing STUN messages
  - Supports all attributes specified in RFC 5389
* Sending and receiving STUN messages over UDP
  - Tracks responses: simply send a request and `await` the response
  - Automatically retransmits requests and handles RTO
* Supports authentication: both long-term and short-term credentials

###STUN Client Example: 

    controller = STUNController(None)
    transport, protocol = await controller.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr)
    request = STUNMessageBuilder(STUNMethod.BINDING, STUNClass.REQUEST)
    response, _, _ = await controller.send_request(request, remote_addr)
    if response.class_ == STUNClass.SUCCESS_RESPONSE:
        x_addr = response.parse_xor_mapped_address()

Also see the various example scripts.

###Todo:

* ICE support.
* TURN support.
