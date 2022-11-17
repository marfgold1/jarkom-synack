import argparse
from pathlib import Path

from lib.connection import Address, Connection, handshake_timeout
from lib.helper import DirectoryValidator, Metadata
from lib.segment import Segment, SegmentFlag, payload_length, signature
from logger import Logger


class Client(object):
    def __init__(
        self,
        path_output: Path,
        client_port=None,
        broadcast_port=1234,
        broadcast_ip='255.255.255.255',
    ):
        self.path_output = path_output
        self.conn = Connection(client_port)
        self.broadcast_addr = Address(
            ip=broadcast_ip,
            port=broadcast_port,
        )
        self.conn.send_data(
            Segment(flags=SegmentFlag(syn=True), payload=signature),
            self.broadcast_addr,
        )
        Logger.log(
            f'[!] [{self.broadcast_addr}] Sent broadcast signature.',
            1,
        )
        ip, port = self.conn.socket.getsockname()
        Logger.log(f'[!] [{ip}:{port}] Client started.', 3)

    def three_way_handshake(self):
        # Three Way Handshake, client-side
        Logger.log(
            '[!] [Handshake] Waiting for server to initate connection',
            3,
        )
        segment, addr = self.conn.listen_single_segment(None)
        if segment.flags.test(syn=True):
            Logger.log(
                f'[!] [Handshake|SYN] [<{addr}] Receive SYN from server', 2,
            )
        Logger.log(
            f'[!] [Handshake|SYN-ACK] [>{addr}] Sending SYN-ACK to the server',
            2,
        )
        self.conn.send_data(
            Segment(flags=SegmentFlag(syn=True, ack=True)),
            addr,
        )
        Logger.log(
            f'[!] [Handshake] [?{addr}] Waiting server response for ACK', 1,
        )
        data = self.conn.listen_single_segment(handshake_timeout, addr)
        if not data:
            Logger.log(
                f'[!] [Handshake|ACK] [?{addr}] Server ACK response timeout.',
                2,
            )
            return False
        segment, addr = data
        if segment.flags.test(ack=True):
            Logger.log(
                f'[!] [Handshake|ACK] [<{addr}] Receive ACK from server', 2,
            )
        return True

    def listen_file_transfer(self):
        # File transfer, client-side
        Logger.log('[!] [File Transfer] Waiting for file transfer...', 3)
        seq_base = 0
        while True:
            segment, addr = self.conn.listen_single_segment(None)
            if segment.flags.test(meta=True):
                file_meta = Metadata.from_bytes(segment.payload)
                # Send ack META
                self.conn.send_data(
                    Segment(
                        flags=SegmentFlag(ack=True, meta=True),
                    ),
                    addr,
                )
                Logger.log([
                    f'[Segment META] [<{addr}] Received META segment',
                    'from the server. Sent META-ACK. Starting file transfer.',
                ], 3)
                break
            Logger.log([
                '[!] [Segment META] Invalid segment, expected META segment.',
                'Ignored.',
            ], 1)
        with open(self.path_output / file_meta.file_name, 'wb') as file:
            last_payload = None
            while True:
                segment, addr = self.conn.listen_single_segment(None, addr)
                if segment.flags.test(meta=True):
                    # Reack META
                    self.conn.send_data(
                        Segment(
                            flags=SegmentFlag(ack=True, meta=True),
                        ),
                        addr,
                    )
                    Logger.log([
                        f'[!] [Segment META] [<{addr}] Received META',
                        'during file transfer. Ignored, resent META-ACK.',
                    ], 1)
                    continue
                if segment.flags.test(fin=True):
                    self.conn.close_socket(addr)
                    break
                if not segment.valid_checksum():
                    # invalid checksum, ignore.
                    Logger.log([
                        f'[Segment SEQ={segment.seq_num}] [<{addr}]',
                        'Invalid checksum. Ignored.',
                    ], 1)
                    continue
                if segment.seq_num < seq_base:
                    # duplicate segment, try to send additional ack
                    # prevent infinite loop for slow connection
                    Logger.log([
                        f'[Segment SEQ={segment.seq_num}] [<{addr}] Duplicate',
                        'segment. Resending additional ACK.',
                    ], 1)
                    self.conn.send_data(
                        Segment(
                            flags=SegmentFlag(ack=True),
                            ack_num=segment.seq_num,
                        ),
                        addr,
                    )
                    continue
                if segment.seq_num == seq_base:
                    if last_payload:
                        file.write(last_payload)
                    last_payload = segment.payload
                    # Acknowledge it
                    self.conn.send_data(
                        Segment(
                            flags=SegmentFlag(ack=True),
                            ack_num=seq_base,
                        ),
                        addr,
                    )
                    Logger.log([
                        f'[Segment SEQ={segment.seq_num}] [<{addr}]',
                        'Received, Ack sent.',
                    ], 2)
                    seq_base += 1
                    continue
                Logger.log([
                    f'[Segment SEQ={segment.seq_num}] [<{addr}] Received',
                    'out-of-order segment. Ignored.',
                ], 1)
            file.write(last_payload[
                :file_meta.file_size % payload_length or payload_length
            ])
        Logger.log(f'[!] [File Transfer] [{addr}] File transfer completed!', 3)


if __name__ == '__main__':
    args_parser = argparse.ArgumentParser(
        description='Client for simple TCP-like file transfer',
    )
    args_parser.add_argument(
        'client_port',
        type=int,
        help='Client port. Set to 0 if you want to use random port.',
    )
    args_parser.add_argument(
        'broadcast_port',
        type=int,
        help='Broadcast port. Default is 1234.',
    )
    args_parser.add_argument(
        'path_output',
        action=DirectoryValidator,
        help='Path to output directory to store the file.',
    )
    args_parser.add_argument(
        '-sh',
        '--server_host',
        default='255.255.255.255',
        help='Server host address, if the server outside the subnet',
    )
    args_parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='Verbosity level.',
    )
    args = args_parser.parse_args()
    default_port = 1234
    main = Client(
        args.path_output,
        args.client_port if args.client_port else None,
        args.broadcast_port if args.broadcast_port else default_port,
        args.server_host,
    )
    Logger.level = args.verbose
    if main.three_way_handshake():
        main.listen_file_transfer()
