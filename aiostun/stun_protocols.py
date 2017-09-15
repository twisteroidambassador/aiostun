"""STUN protocols and transports."""

import asyncio
import logging
import ipaddress
from functools import partial
from concurrent.futures import FIRST_COMPLETED

from .stun_messages import (STUNMessageParser,
                            STUNMessageBuilder,
                            STUNClass,
                            random_trans_id)
from .exceptions import (InvalidSTUNMessage,
                         STUNTransactionTimeout,
                         )
from .pacers import (FixedRTOPacer, ClassicRTOPacer)
from .utils import (HoldExpiringMapping)

LOG_THRESHOLD_FOR_CONNLOST_WRITES = 5


class _STUNBridgeProtocol(asyncio.DatagramProtocol):
    """Share a DatagramTransport between DatagramProtocol and STUNController."""
    
    def __init__(self, child_protocol: asyncio.DatagramProtocol,
                 stun_controller: 'STUNController'):
        self._child_protocol = child_protocol
        self._stun_controller = stun_controller
        self._transport = None  # type: asyncio.DatagramTransport
    
    def connection_made(self, transport):
        self._transport = transport
        self._stun_controller.connection_made(transport)
        self._child_protocol.connection_made(transport)
    
    def connection_lost(self, exc):
        self._child_protocol.connection_lost(exc)
        self._stun_controller.connection_lost(exc)
    
    def pause_writing(self):
        self._child_protocol.pause_writing()
    
    def resume_writing(self):
        self._child_protocol.resume_writing()
    
    def datagram_received(self, data, addr):
        try:
            parser = STUNMessageParser(data)
        except InvalidSTUNMessage:
            self._child_protocol.datagram_received(data, addr)
        else:
            local_addr = self._transport.get_extra_info('sockname')
            self._stun_controller.stun_message_received(
                parser, addr, local_addr)
    
    def error_received(self, exc):
        self._child_protocol.error_received(exc)
        self._stun_controller.error_received(exc)


class STUNController:
    """Send and receive STUN messages.

    Properties:

    request_cb, remember_requests, remember_responses: see __init__().
    """
    TREAT_SPURIOUS_RESPONSE_AS_NON_STUN = True
    CACHE_INCOMING_RESPONSES = 16
    CACHE_OUTGOING_RESPONSES = 40

    def __init__(self, request_cb, *, remember_requests=None,
                 remember_responses=None, pacer=None, request_tracker=None,
                 loop=None):
        """Initialize instance.

        Arguments:

        request_cb: a callback function or coroutine which will be called
        when a request or indication is received. It will be called with
        arguments (parser, remote_addr, local_addr).

        If the incoming message requires a response, request_cb() should usually
        return a STUNMessageBuilder instance. The message will be built and sent
        back where the request came from. If the response requires some other
        action, e.g. sending from a different socket, sending to another
        destination, etc., then a function/callable can be returned (not a
        coroutine/awaitable), which will be called. If a response is not
        required, then None can be returned. All these return values will be
        remembered if remember_requests is greater than 0. To explicitly
        suppress the remembering behavior, return a literal False. In this case,
        any responding must be done manually.

        See Notes for a description of the remembering behavior.

        remember_requests: number of seconds to remember incoming requests.
        See Notes for the remembering behavior.

        remember_responses: number of seconds to remember incoming responses.
        See Notes for the remembering behavior.

        pacer: a pacer object that controls number of resends and delay between
        resends.

        request_tracker: can be used to share requests tracking between several
        controllers. Should be a HoldExpiringMapping instance.

        loop: the asyncio event loop used.


        Notes on "remembering":

        Quote from RFC 5389 Section 7.3.1:

            When run over UDP, a request received by the server could be the
            first request of a transaction, or a retransmission.  The server
            MUST respond to retransmissions such that the following property
            is preserved: if the client receives the response to the
            retransmission and not the response that was sent to the original
            request, the overall state on the client and server is identical
            to the case where only the response to the original
            retransmission is received, or where both responses are received
            (in which case the client will use the first).  The easiest way
            to meet this requirement is for the server to remember all
            transaction IDs received over UDP and their corresponding
            responses in the last 40 seconds.  However, this requires the
            server to hold state, and will be inappropriate for any requests
            which are not authenticated.  Another way is to reprocess the
            request and recompute the response.  The latter technique MUST
            only be applied to requests that are idempotent (a request is
            considered idempotent when the same request can be safely
            repeated without impacting the overall state of the system) and
            result in the same success response for the same request.

        This module implements code to help with the "remembering" mentioned
        above, and a bit more.

        For the purposes below, two messages are "identical" if the entirety of
        the message data (including header and attributes), the remote address
        and the local address are all equal between them. It is assumed that
        all retransmissions are identical to the original.

        For incoming requests and indications:

        If remember_requests == 0, then no remembering takes place. Each
        incoming message invokes a call to request_cb() even if it's identical
        to a previous one, and code using this module is responsible for abiding
        to the RFC. In particular, if request_cb() is a coroutine, then it is
        possible that an identical message may arrive, and request_cb() called
        again, before the previous invocation is done.

        If remember_requests > 0, then incoming messages are normally
        remembered. If an identical message arrives while a coroutine
        request_cb() is not yet done, request_cb() will not be called again,
        and when request_cb() becomes done the action returned by it will be
        repeated the appropriate number of times. When request_cb()
        completes, the message and the returned action are remembered for
        remember_requests seconds. If an identical message then arrives
        before the "memory" expires, the action is repeated without calling
        request_cb(). The exception here is that, if request_cb() returns a
        literal False, then the message is not remembered afterwards.

        For incoming responses:

        If remember_responses == 0, then the responses are not remembered. The
        first response to an ongoing request will be delivered to the
        send_request coroutine, and any subsequent identical responses will
        be treated like any other spurious response that does not correspond
        to any ongoing request, which means they may be delivered to the
        associated DatagramProtocol as a non-STUN packet.

        If remember_responses > = 0, then a response received for an ongoing
        request will be remembered for remember_responses seconds. If an
        identical response subsequently arrives when the memory has not expired
        yet, it will be ignored. (If a different response to the request
        arrives, however, it will still be treated as a spurious response
        without a corresponding request.)

        remember_requests and remember_responses have reasonable defaults.
        Usually they should be left at the default values if the remembering
        behavior is desired, or both set to 0 if remembering is not desired.
        """
        self._loop = loop if loop else asyncio.get_event_loop()
        self.request_cb = request_cb
        self._pacer = pacer if pacer is not None else ClassicRTOPacer()
        self._request_tracker = (request_tracker if request_tracker is not None
                                 else HoldExpiringMapping())
        if remember_responses is not None:
            self.remember_responses = remember_responses
        else:
            self.remember_responses = self.CACHE_INCOMING_RESPONSES
        if remember_requests is not None:
            self.remember_requests = remember_requests
        else:
            self.remember_requests = self.CACHE_OUTGOING_RESPONSES

        self._protocol = None  # type:asyncio.DatagramProtocol
        self._logger = logging.getLogger('aiostun.controller')
        self._cache = HoldExpiringMapping()
        self._transport = None  # type: asyncio.DatagramTransport
        self._conn_lost = 0

    async def create_datagram_endpoint(self, protocol_factory, local_addr=None,
                                       remote_addr=None, **kwargs):
        """Create datagram connection for this controller.

        Arguments:

        protocol_factory: a callable that returns an asyncio.DatagramProtocol
        subclass instance.

        local_addr, remote_addr, **kwargs: These arguments are passed to
        loop.create_datagram_endpoint(). Usually local_addr should be set to
        the address of a local network interface, and remote_addr left
        unspecified.


        Returns (transport, protocol).

        transport: an asyncio.DatagramTransport instance for the underlying
        connection. Can be used to send non-STUN datagrams.

        datagram_protocol: an asyncio.DatagramProtocol instance, created by
        protocol_factory, which should respond to non-STUN datagrams received
        in this connection.
        """
        datagram_protocol = protocol_factory()
        self._protocol = datagram_protocol
        bridge_factory = partial(_STUNBridgeProtocol, datagram_protocol, self)
        transport, bridge_protocol = await self._loop.create_datagram_endpoint(
            bridge_factory, local_addr, remote_addr, **kwargs)
        return transport, datagram_protocol

    def connection_made(self, transport):
        self._logger.debug('connection_made, transport: %r', transport)
        self._transport = transport

    def connection_lost(self, exc):
        self._logger.debug('connection_lost, exc: %r', exc)
        self._conn_lost += 1

    def stun_message_received(self, parser: STUNMessageParser,
                              remote_addr, local_addr):
        self._logger.debug('received STUN message, class: %r', parser.class_)
        cache_key = (parser.data, remote_addr, local_addr)
        try:
            action = self._cache[cache_key]
        except KeyError:
            pass
        else:
            self._logger.debug('cache hit for message')
            if action is not None:
                action()
            return

        if parser.class_ in (STUNClass.REQUEST, STUNClass.INDICATION):
            response = self.request_cb(parser, remote_addr, local_addr)
            try:
                fut = asyncio.ensure_future(response, loop=self._loop)
            except TypeError:  # response is not a coroutine/future/awaitable
                self._submit_response(response, remote_addr, cache_key)
            else:  # response is an coroutine/future/awaitable
                resend_counter = [0]
                if self.remember_requests:
                    def increment_counter():
                        resend_counter[0] += 1

                    self._cache[cache_key] = increment_counter
                asyncio.ensure_future(self._submit_response_async(
                        fut, remote_addr, cache_key, resend_counter
                    ), loop=self._loop)
        else:
            try:
                preprocessor = self._request_tracker[parser.trans_id]
            except KeyError:
                self._logger.debug('Response trans_id does not match ongoing '
                                   'transaction, discarding')
                if self.TREAT_SPURIOUS_RESPONSE_AS_NON_STUN:
                    self._protocol.datagram_received(
                        parser.data, remote_addr)
                return
            self._logger.debug('Response trans_id matches ongoing transaction')
            response_fut = preprocessor(parser)  # type: asyncio.Future
            if response_fut is None:
                self._logger.debug('Response rejected by preprocesser')
                if self.TREAT_SPURIOUS_RESPONSE_AS_NON_STUN:
                    self._protocol.datagram_received(
                        parser.data, remote_addr)
                return
            else:
                self._logger.debug('Response accepted')
                response_fut.set_result((parser, remote_addr, local_addr))
                if self.remember_responses:
                    self._cache.add(cache_key, None,
                                    self.remember_responses)
                return

    def error_received(self, exc):
        self._logger.debug('error_received, exc: %r', exc)

    async def _submit_response_async(self, response_fut,
                                     remote_addr, resend_counter, cache_key):
        try:
            response = await response_fut
        finally:
            try:
                del self._cache[cache_key]
            except KeyError:
                pass
        resends = resend_counter[0]
        self._submit_response(response, remote_addr, cache_key, resends)

    def _submit_response(self, response, remote_addr, cache_key, resends=0):
        if response is False:  # Must check for explicit False here
            return
        if response is None:
            sender = None
        else:
            if callable(response):
                sender = response
            else:
                msg = response.build()
                sender = partial(self._transport.sendto, msg, remote_addr)
            for _ in range(resends + 1):
                sender()
        if self.remember_requests:
            self._cache.add(cache_key, sender, self.remember_requests)

    async def send_request(self, builder: 'STUNMessageBuilder', remote_addr,
                           key=None, require_fingerprint=None, *, pacer=None):
        """Send a STUN request and wait for a response. This is a coroutine.

        Arguments:

        builder: a STUNMessageBuilder for the message to be sent.

        remote_addr: address to send to. This should be a tuple returned
        by getaddrinfo(), get_endpoints_towards() or similar. The first element
        of the tuple must be an IP address, not a host name.

        key: key used to authenticate the response. If None, will be copied
        from builder. If False (a literal False, not a "falsy" value),
        disables authentication checking,

        require_fingerprint: whether the response should have FINGERPRINT. If
        None, will be copied from builder.want_fingerprint.

        Returns (parser, remote_addr, local_addr) if a response is received,
        and raises STUNTransactionTimeout if no response is received after
        all resend attempts are exhausted.
        """
        if self._conn_lost:
            if self._conn_lost > LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                self._logger.warning(
                    'Attempted to send STUN message after connection lost')
            self._conn_lost += 1
            return

        pacer = pacer if pacer is not None else self._pacer

        self._logger.debug('Making STUN request')
        if key is None:
            key = builder.key
        elif key is False:
            key = None
        if require_fingerprint is None:
            require_fingerprint = builder.want_fingerprint
        remote_ip = ipaddress.ip_address(remote_addr[0])

        if builder.trans_id is not None:
            builder.trans_id = random_trans_id()
            while builder.trans_id in self._request_tracker:
                builder.trans_id = random_trans_id()
        else:
            if builder.trans_id in self._request_tracker:
                raise RuntimeError('STUN request transaction ID conflict with '
                                   'ongoing transaction')
        self._logger.debug('Request transaction ID: %r', builder.trans_id)
        msg = builder.build()

        response_fut = self._loop.create_future()
        preprocess = partial(self._preprocess_response, response_fut,
                             key=key, require_fingerprint=require_fingerprint)
        send_time = self._loop.time()
        with self._request_tracker.hold(builder.trans_id, preprocess):
            for wait_time in pacer.get_wait_times(remote_ip):
                self._logger.debug('Sending STUN request message, will then '
                                   'wait %f s', wait_time)
                self._transport.sendto(msg, remote_addr)
                # try:
                #     response = await asyncio.wait_for(
                #         asyncio.shield(response_fut, loop=self._loop),
                #         wait_time, loop=self._loop)
                # except asyncio.TimeoutError:
                #     send_time = None
                #     continue
                # else:
                #     self._logger.debug('STUN request received response')
                #     if send_time is not None:
                #         pacer.report_rtt(remote_ip, self._loop.time()-send_time)
                #     return response
                done, pending = await asyncio.wait((response_fut,),
                                                   loop=self._loop,
                                                   timeout=wait_time,
                                                   return_when=FIRST_COMPLETED)
                if done:
                    response = response_fut.result()
                    self._logger.debug('STUN request received response')
                    if send_time is not None:
                        pacer.report_rtt(remote_ip, self._loop.time()-send_time)
                    return response
                else:
                    send_time = None
            self._logger.debug('All resends exhausted')
            response_fut.cancel()
            raise STUNTransactionTimeout

    @staticmethod
    def _preprocess_response(ret, parser: STUNMessageParser, *,
                             key=None, require_fingerprint=False):
        """Process an incoming response, potentially discarding it silently.

        Returns None if the response should be silently discarded, otherwise
        return ret.

        References:
        https://tools.ietf.org/html/rfc5389 (Sections 7 and 10)
        """
        if require_fingerprint and not parser.has_fingerprint:
            return None
        if (key is not None) and not (
                parser.class_ == STUNClass.SUCCESS_RESPONSE
                and parser.has_message_integrity
                and parser.check_message_integrity(key)):
            return None
        return ret

    def send_indication(self, builder: 'STUNMessageBuilder', remote_addr):
        """Send a STUN indication.

        Arguments:

        builder: a STUNMessageBuilder for the message to be sent.

        remote_addr: address to send to. This should be a tuple returned
        by getaddrinfo(), get_endpoints_towards() or similar. The first element
        of the tuple must be an IP address, not a host name.
        """
        if self._conn_lost:
            if self._conn_lost > LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                self._logger.warning(
                    'Attempted to send STUN message after connection lost')
            self._conn_lost += 1
            return
        self._logger.debug('Sending STUN indication')
        msg = builder.build()
        self._transport.sendto(msg, remote_addr)
