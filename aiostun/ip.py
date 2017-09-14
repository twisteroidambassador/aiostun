"""Discovery and gathering of local IP addresses."""

import asyncio
#import ipaddress
#import socket

async def get_endpoints_towards(remote_addr, *, loop=None):
    """Discover local and remote address that would be used to connect to
    remote_addr.

    Returns (remote_addr, local_addr).
    local_addr is always a 2-tuple of (address, port), suitable for passing into
    loop.create_datagram_endpoint(). remote_addr is in the original format
    returned, so e.g. for IPv6 addresses it will be a 4-tuple.
    """
    if loop is None:
        loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=remote_addr)
    sockname = transport.get_extra_info('sockname')
    peername = transport.get_extra_info('peername')
    transport.abort()
    return peername, sockname[:2]
