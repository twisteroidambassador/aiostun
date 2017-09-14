import typing
import ipaddress
import logging
from collections import namedtuple

from .utils import HoldExpiringMapping

IPAddressType = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class Pacer:
    """Base class for pacer objects.

    Pacers are responsible for pacing STUN message resends."""

    def get_wait_times(self, ip: IPAddressType):
        """Get the retransmission wait times for destination ip.

        Arguments:

        ip: an IPv4Address or IPv6Address object denoting the IP address of the
        remote peer.

        Return an iterable of wait times between retransmits and after last
        retransmit.
        """
        raise NotImplementedError

    def report_rtt(self, ip: IPAddressType, rtt):
        """Report a successful RTT measurement.

        Arguments:

        ip: an IPv4Address or IPv6Address object denoting the IP address of the
        remote peer.

        rtt: RTT measurement sample.
        """
        raise NotImplementedError


class FixedRTOPacer(Pacer):
    def __init__(self, rto=0.5, rc=7, rm=16):
        self.rto = rto
        self.rc = rc
        self.rm = rm

    def get_wait_times(self, ip):
        return (*(self.rto * (2 ** retry) for retry in range(self.rc - 1)),
                self.rto * self.rm)

    def report_rtt(self, ip, rtt):
        pass


class ClassicRTOPacer(Pacer):
    """Pace messages with the classic TCP retransmission timer.

    Reference:
    https://tools.ietf.org/html/rfc6298
    https://tools.ietf.org/html/rfc5389#section-7.2.1
    """
    ALPHA = 1/8
    BETA = 1/4
    K = 4

    def __init__(self, init_rto=0.5, rc=7, rm=16, *,
                 min_rto=0.1, max_rto=1, stale_timeout=600):
        self.init_rto = init_rto
        self.rc = rc
        self.rm = rm
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.stale_timeout = stale_timeout
        self._store = HoldExpiringMapping()
        self._logger = logging.getLogger('aiostun.pacer.classic')

    def _get_record(self, ip: IPAddressType):
        try:
            return self._store[ip.packed]
        except KeyError:
            return self.init_rto, None, None

    def _set_record(self, ip: IPAddressType, rto, srtt, rttvar):
        rto = max(self.min_rto, min(self.max_rto, rto))
        self._store.add(ip.packed, (rto, srtt, rttvar), self.stale_timeout)

    def _update_rto(self, ip: IPAddressType, rto):
        orig_rto, srtt, rttvar = self._get_record(ip)
        rto = max(rto, orig_rto)
        self._set_record(ip, rto, srtt, rttvar)

    def get_wait_times(self, ip: IPAddressType):
        self._logger.debug('Generating wait times for %r', ip)
        first_rto, _, _ = self._get_record(ip)
        self._logger.debug('Initial RTO: %f', first_rto)
        yield first_rto

        for i in range(1, self.rc - 1):
            rto = first_rto * (2 ** i)
            self._logger.debug('Backing off RTO to %f and updating record', rto)
            self._update_rto(ip, rto)
            yield rto
        rto = first_rto * self.rm
        self._logger.debug('Final wait of %f and updating record', rto)
        self._update_rto(ip, rto)
        yield rto

    def report_rtt(self, ip: IPAddressType, rtt):
        self._logger.debug('Got new RTT measurement for %r at %f', ip, rtt)
        _, srtt, rttvar = self._get_record(ip)
        if srtt is None or rttvar is None:
            self._logger.debug('Initializing stats for %r', ip)
            srtt = rtt
            rttvar = rtt / 2
        else:
            rttvar = (1 - self.BETA) * rttvar + self.BETA * abs(srtt - rtt)
            srtt = (1 - self.ALPHA) * srtt + self.ALPHA * rtt
        rto = srtt + self.K * rttvar
        self._logger.debug('Updating: SRTT = %f, RTTVAR = %f, RTO = %f',
                           srtt, rttvar, rto)
        self._set_record(ip, rto, srtt, rttvar)

