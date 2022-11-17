import argparse
from lib.connection import Address, Connection
from lib.segment import Segment, SegmentFlag

class Server:
    def __init__(self, path_file, port=1234):
        # Init server
        self.path_file = path_file
        self.file_size = 0
        self.conn = Connection(port)
        self.clients = []
        ip, port = self.conn.socket.getsockname()
        print('[!] Server started at', f'{ip}:{port}')
        pass

    def listen_for_clients(self):
        # Waiting client for connect
        print('[!] Listening to broadcast address for clients.')
        segment, addr = self.conn.listen_single_segment()
        if segment.flags.test(syn=True):
            print(
                '[!] Received request from',
                f'{addr.ip}:{addr.port}',
            )
            self.clients.append(addr)
            return
        else:
            print(
                '[!] Received unknown segment from',
                f'{addr.ip}:{addr.port}',
            )

    def start_file_transfer(self):
        # Handshake & file transfer for all client
        pass

    def file_transfer(self, client_addr: Address):
        # File transfer, server-side, Send file to 1 client
        pass

    def three_way_handshake(self, client_addr: Address) -> bool:
       # Three way handshake, server-side, 1 client
        print(
            '[!] [Handshake|SYN] Sending SYN to client with address:',
            f'{client_addr.ip}:{client_addr.port}',
        )
        self.conn.send_data(
            Segment(flags=SegmentFlag(syn=True)),
            client_addr,
        )
        print('[!] [Handshake] Waiting for client SYN-ACK...')
        segment, addr = self.conn.listen_single_segment()
        if segment.flags.test(syn=True, ack=True):
            print(
                '[!] [Handshake|SYN-ACK] Receive SYN-ACK',
                'from client with address:',
                f'{addr.ip}:{addr.port}',
            )
        print('[!] [Handshake|ACK] Sending ACK to the client...')
        self.conn.send_data(
            Segment(flags=SegmentFlag(ack=True)),
            client_addr,
        )
        print('[!] [Handshake] Connection established!')


if __name__ == '__main__':
    args_parser = argparse.ArgumentParser(
        description='Client for simple TCP-like file transfer',
    )
    args_parser.add_argument(
        'broadcast_port',
        type=int,
        help='Broadcast port. Default is 1234.',
    )
    args = args_parser.parse_args()
    main = Server(
        args.path_file_input,
        port=args.broadcast_port,
    )
    main.listen_for_clients()
    main.start_file_transfer()
