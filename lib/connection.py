import socket
from .segment import Segment
from typing import NamedTuple


class Address(NamedTuple):
    ip: str
    port: int


class Connection:
    def __init__(self, bind_port: int | None = None):
        # Init UDP socket
        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
        )
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.settimeout(0.1)
        if bind_port:
            self.socket.bind(Address(ip='', port=bind_port))

    def send_data(self, msg: Segment, dest: Address):
        # Send single segment into destination
        self.socket.sendto(msg.to_bytes(), dest)

    def listen_single_segment(self) -> Segment:
        # Listen single UDP datagram within timeout and convert into segment
        pass

    def close_socket(self):
        # Release UDP socket
        pass
