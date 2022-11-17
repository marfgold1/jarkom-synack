import socket
import time
from collections import defaultdict
from queue import Queue
from threading import Thread
from typing import NamedTuple, Tuple

from lib.segment import Segment, SegmentFlag, segment_length
from logger import Logger

signature_buffer = 'signature'
handshake_timeout = 3


class Address(NamedTuple):
    ip: str
    port: int

    def __str__(self) -> str:
        return f'{self.ip}:{self.port}'


class Connection(object):
    def __init__(self, bind_port: int | None = None, parallel=False):
        # Init UDP socket
        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
        )
        self.parallel = parallel
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.buffer = defaultdict(Queue)
        if bind_port:
            self.socket.bind(Address(ip='', port=bind_port))
        if self.parallel:
            thread = Thread(target=self._buffer)
            thread.daemon = True
            thread.start()
        else:
            self.socket.settimeout(0.1)

    def send_data(self, msg: Segment, dest: Address):
        # Send single segment into destination
        self.socket.sendto(msg.to_bytes(), dest)

    def listen_single_segment(
        self,
        timeout=0.1,
        address: Address | str = None,
    ) -> Tuple[Segment, Address] | None:
        # Listen single UDP datagram within timeout and convert into segment
        start_time = time.time()
        while True:
            if self.parallel:
                data = self._parallel_listen(address)
            else:
                data = self._normal_listen(address)
            if data is None:
                if timeout and time.time() - start_time > timeout:
                    Logger.log('[!] Timeout!', 0)
                    return None
            else:
                segment, addr = data
                break
        if not isinstance(segment, Segment):
            segment = Segment.from_bytes(segment)
        if segment.flags.test(fin=True):
            Logger.log(f'[!] [Handshake|FIN] [<{addr}] Received FIN.', 2)
            self.send_data(
                Segment(flags=SegmentFlag(fin=True, ack=True)),
                addr,
            )
            Logger.log(f'[!] [Handshake|FIN-ACK] [>{addr}] Sent FIN-ACK.', 2)
        return segment, addr

    def close_socket(self, client_addr: Address):
        # Release UDP socket
        Logger.log(f'[!] [Handshake|FIN] [>{client_addr}] Sending FIN.', 2)
        self.send_data(
            Segment(flags=SegmentFlag(fin=True)),
            client_addr,
        )
        Logger.log(f'[!] [Handshake] [?{client_addr}] Waiting for FIN-ACK.', 1)
        data = self.listen_single_segment(handshake_timeout, client_addr)
        if data is None:
            Logger.log([
                f'[!] [Handshake|FIN-ACK] [{client_addr}] FIN-ACK',
                'not received. Assuming connection closed.',
            ], 3)
            return
        segment, addr = data
        if segment.flags.test(fin=True, ack=True):
            Logger.log(f'[!] [<{addr}] Received FIN-ACK.', 2)

    def _parallel_listen(
        self,
        address: Address | str,
    ) -> Tuple[Segment, Address] | None:
        if address and not self.buffer[address].empty():
            data = self.buffer[address].get()
            if isinstance(address, Address):
                return data, address
            return data
        return None  # we let the thread handle the buffer and infloop

    def _normal_listen(
        self,
        address: Address,
    ) -> Tuple[Segment, Address] | None:
        try:
            segment, addr = self.socket.recvfrom(segment_length)
        except TimeoutError:
            return None
        except KeyboardInterrupt:
            exit(0)
        addr = Address(*addr)
        if not address or addr == address:
            return segment, addr
        else:
            Logger.log(
                f'[!] Received segment from unknown address {addr}',
                1,
            )
        return None

    def _buffer(self):
        while True:
            try:
                segment, addr = self.socket.recvfrom(segment_length)
            except socket.error:
                continue
            segment = Segment.from_bytes(segment)
            addr = Address(*addr)
            if segment.is_signature():
                self.buffer[signature_buffer].put((segment, addr))
            else:
                self.buffer[addr].put(segment)
