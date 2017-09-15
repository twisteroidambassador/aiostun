import asyncio
import logging
import traceback
import argparse

from aiostun import (STUNController, STUNMessageBuilder,
                     STUNMethod, STUNClass, get_endpoints_towards)


async def simple_stun_client(host, port):
    try:
        logging.info('Using STUN server at host {!r}, port {!r}'.format(
            host, port))
        remote_addr, local_addr = await get_endpoints_towards((host, port))
        logging.info('Using local address {!r}, remote address {!r}'.format(
            local_addr, remote_addr))
        controller = STUNController(None)
        transport, protocol = await controller.create_datagram_endpoint(
            asyncio.DatagramProtocol, local_addr)
        request = STUNMessageBuilder(STUNMethod.BINDING, STUNClass.REQUEST)
        response, _, _ = await controller.send_request(request, remote_addr)
        if response.class_ == STUNClass.SUCCESS_RESPONSE:
            logging.info('Received STUN success response')
            try:
                x_addr = response.parse_xor_mapped_address()
            except LookupError:  # MissingSTUNAttribute derives from LookupError
                logging.info('Server did not return an XOR-MAPPED-ADDRESS '
                             'attribute: it is not RFC 5389 compliant')
            else:
                logging.info('XOR-MAPPED-ADDRESS: {!r}'.format(x_addr))
                return x_addr
            try:
                addr = response.parse_mapped_address()
            except LookupError:
                logging.info('Server did not return a MAPPED-ADDRESS attribute')
                raise
            else:
                logging.info('MAPPED-ADDRESS: {!r}'.format(addr))
                return addr
        else:
            logging.info('Received STUN message of class {!r}'.format(
                response.class_))
            raise RuntimeError
    except Exception:
        traceback.print_exc()
        raise


def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Simple STUN client.')
    parser.add_argument('host', help='STUN server host.')
    parser.add_argument('port', help='STUN server port.',
                        type=int, nargs='?', default=3478)
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    addr = loop.run_until_complete(simple_stun_client(args.host, args.port))
    print('Our address: {!r}'.format(addr))


if __name__ == '__main__':
    main()
