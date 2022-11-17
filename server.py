import argparse
from concurrent.futures import ThreadPoolExecutor
from io import BufferedReader
from math import ceil
from pathlib import Path

from config import config
from lib.connection import Address, Connection
from lib.connection import signature_buffer as sign_buf
from lib.helper import FileValidator, Metadata
from lib.segment import Segment, SegmentFlag, payload_length
from logger import Logger


class Server:
    def __init__(self, path_file: Path, port=1234, parallel=False):
        # Init server
        self.path_file = path_file
        self.conn = Connection(port, parallel)
        self.clients = []
        self.parallel = parallel
        ip, port = self.conn.socket.getsockname()
        # Get file size
        with open(self.path_file, 'rb') as file:
            file.seek(0, 2)  # Seek to end
            self.file_size = file.tell()
        Logger.log(f'[!] [{ip}:{port}] Server started.', 3)

    def listen_for_clients(self):
        # Waiting client for connect
        Logger.log('[!] Listening to broadcast address for clients.', 3)
        executor = ThreadPoolExecutor()
        while True:
            segment, addr = self.conn.listen_single_segment(
                timeout=None,
                address=sign_buf if self.parallel else None,
            )
            if segment.is_signature():
                Logger.log(f'[!] [<{addr}] Received signature request.', 3)
                self.clients.append(addr)
                if self.parallel:
                    executor.submit(
                        self.parallel_file_transfer,
                        self.clients.pop(),
                    )
                else:
                    if (input('[?] Listen more? ([y]/n) ') or 'y') != 'y':
                        break
            else:
                Logger.log(f'[!] [<{addr}] Received unknown segment.', 1)
        if not self.parallel:
            Logger.log('[!] Commencing file transfer...', 3)
            for client in self.clients:
                self.file_transfer(client)
        else:
            executor.submit(self.parallel_file_transfer, self.clients.pop())
        executor.shutdown(wait=True, cancel_futures=False)

    def parallel_file_transfer(self, client: Address):
        # Parallel file transfer
        Logger.log('[!] Commencing parallel file transfer...', 3)
        self.file_transfer(client)

    def __send_file_segment(
        self,
        file: BufferedReader,
        seq: int,
        client_addr: Address,
    ):
        # Send file segment to client
        file.seek(seq * payload_length)
        self.conn.send_data(
            Segment(
                seq_num=seq,
                payload=file.read(payload_length),
            ),
            client_addr,
        )
        Logger.log(f'[Segment SEQ={seq}] [>{client_addr}] Sent.', 2)

    def file_transfer(self, client_addr: Address):
        if not self.three_way_handshake(client_addr):
            Logger.log([
                f'[!] [File Transfer] [{client_addr}]',
                'Client handshake failed.',
            ], 3)
            return
        # File transfer, server-side, Send file to 1 client
        seq_base = 0
        current_retry = 0
        seq_len = ceil(self.file_size / payload_length)
        Logger.log([
            f'[!] [File Transfer] [{client_addr}] Begin send file to client',
            f'({seq_len} segments).',
        ], 3)
        # Send metadata
        while True:
            self.conn.send_data(
                Segment(
                    flags=SegmentFlag(meta=True),
                    payload=Metadata(
                        self.file_size,
                        seq_len,
                        self.path_file.name,
                    ).to_bytes(),
                ),
                client_addr,
            )
            Logger.log(
                f'[!] [File Transfer] [{client_addr}] Sent META to client.',
                2,
            )
            # Wait for META-ACK
            data = self.conn.listen_single_segment(
                config.TIMEOUT_HANDSHAKE,
                client_addr,
            )
            if data is None or not data[0].flags.test(meta=True, ack=True):
                Logger.log([
                    f'[!] [File Transfer] [{client_addr}]',
                    'Client did not respond to META. Resend META.',
                ], 1)
                current_retry += 1
                if current_retry > config.MAX_RETRY:
                    Logger.log([
                        f'[!] [File Transfer] [{client_addr}]',
                        'Max retries reached for META.',
                        'Aborted (assuming connection closed).',
                    ], 3)
                    return
            else:
                break
        current_retry = 0
        # Send file
        with open(self.path_file, 'rb') as file:
            while seq_base < seq_len:  # loop for entire length segment
                seq_max = min(seq_base + config.WINDOW_SIZE, seq_len)
                for seq in range(seq_base, seq_max):
                    self.__send_file_segment(file, seq, client_addr)
                while seq_base < seq_len:  # loop for all ack
                    # Wait for ACK
                    data = self.conn.listen_single_segment(
                        config.TIMEOUT_FILE,
                        client_addr,
                    )
                    # if timeout, go back n
                    if data is None:
                        current_retry += 1
                        # we limit go back n to max_tries times
                        if current_retry > config.MAX_RETRY:
                            Logger.log([
                                f'[!] [File Transfer] [{client_addr}] Max',
                                'retry reached, assuming connection closed.',
                            ], 3)
                            return
                        Logger.log([
                            f'[Segment SEQ={seq_base}] NOT ACKED.',
                            'Timeout.',
                        ], 1)
                        break
                    # data is available
                    # reset tries counter
                    current_retry = 0
                    # read data
                    segment, addr = data
                    if all([
                        segment.flags.test(ack=True),
                        segment.ack_num == seq_base,
                    ]):
                        Logger.log([
                            f'[Segment SEQ={segment.ack_num}] [{addr}]',
                            'Acked.',
                        ], 2)
                        seq_base += 1
                        # Send next seq if available
                        if seq_base + config.WINDOW_SIZE - 1 < seq_len:
                            self.__send_file_segment(
                                file,
                                seq_base + config.WINDOW_SIZE - 1,
                                client_addr,
                            )
                    else:
                        Logger.log([
                            f'[Segment SEQ={segment.ack_num}] [{addr}] NOT',
                            f'ACKED. Different ack num than {seq_base}.',
                            'Ignored.',
                        ], 1)
        # Tear down connection
        Logger.log([
            f'[!] [File Transfer] [{client_addr}] File transfer',
            'completed!',
        ], 3)
        self.conn.close_socket(client_addr)
        Logger.log([
            f'[!] [Handshake] [?{client_addr}]',
            f'Waiting for FIN from {client_addr}.',
        ], 1)
        data = self.conn.listen_single_segment(
            config.TIMEOUT_HANDSHAKE,
            client_addr,
        )
        if data is None:
            Logger.log([
                f'[!] [Handshake] [{client_addr}] FIN not received.',
                'Assuming connection closed.',
            ], 3)
        else:
            Logger.log(f'[!] [x{client_addr}] Connection closed!', 3)

    def three_way_handshake(self, client_addr: Address) -> bool:
        # Three way handshake, server-side, 1 client
        Logger.log([
            f'[!] [Handshake|SYN] [>{client_addr}]',
            'Sending SYN to client.',
        ], 2)
        self.conn.send_data(
            Segment(flags=SegmentFlag(syn=True)),
            client_addr,
        )
        Logger.log([
            f'[!] [Handshake] [?{client_addr}]',
            'Waiting for client SYN-ACK...',
        ], 1)
        data = self.conn.listen_single_segment(
            config.TIMEOUT_HANDSHAKE,
            client_addr,
        )
        if data is None:
            Logger.log([
                f'[!] [Handshake] [{client_addr}]',
                'SYN-ACK timeout, assuming connection closed.',
            ], 1)
            return False
        segment = data[0]
        if segment.flags.test(syn=True, ack=True):
            Logger.log(
                f'[!] [Handshake|SYN-ACK] [<{client_addr}] Received SYN-ACK.',
                2,
            )
        self.conn.send_data(
            Segment(flags=SegmentFlag(ack=True)),
            client_addr,
        )
        Logger.log(
            f'[!] [Handshake|ACK] [>{client_addr}] Sent ACK to the client.',
            2,
        )
        Logger.log(
            f'[!] [Handshake] [{client_addr}] Connection established!',
            2,
        )
        return True


if __name__ == '__main__':
    args_parser = argparse.ArgumentParser(
        description='Client for simple TCP-like file transfer',
    )
    args_parser.add_argument(
        'broadcast_port',
        type=int,
        help='Broadcast port. Default is 1234.',
    )
    args_parser.add_argument(
        'path_file_input',
        action=FileValidator,
        help='Path for input file to send into the clients.',
    )
    args_parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=config.VERBOSE,
        help='Verbosity level.',
    )
    args_parser.add_argument(
        '-p',
        '--parallel',
        action='store_true',
        help='Send file to all clients in parallel.',
    )
    args_parser.add_argument(
        '-t',
        '--timeout',
        type=float,
        nargs='+',
        default=[config.TIMEOUT_HANDSHAKE, config.TIMEOUT_FILE],
        help=' '.join([
            'Timeout for handshake and file transfer.',
            'Specify one value to set both the same value.',
        ]),
    )
    args_parser.add_argument(
        '-ws',
        '--window-size',
        type=int,
        default=config.WINDOW_SIZE,
        help='Window size for file transfer.',
    )
    args_parser.add_argument(
        '-r',
        '--max-retry',
        type=int,
        default=5,
        help='Max retry for file transfer.',
    )
    args = args_parser.parse_args()
    if len(args.timeout) > 2:
        args_parser.error('Too many timeout values.')
    elif len(args.timeout) == 1:
        config.TIMEOUT_HANDSHAKE = args.timeout[0]
        config.TIMEOUT_FILE = args.timeout[0]
    else:
        config.TIMEOUT_HANDSHAKE = args.timeout[0]
        config.TIMEOUT_FILE = args.timeout[1]
    config.WINDOW_SIZE = args.window_size
    config.MAX_RETRY = args.max_retry
    main = Server(
        args.path_file_input,
        port=args.broadcast_port,
        parallel=args.parallel,
    )
    Logger.level = args.verbose
    main.listen_for_clients()
