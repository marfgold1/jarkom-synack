import struct
from dataclasses import astuple, dataclass
from typing import Type

# Constants
# ---------
# The struct_format consist of following format:
# ! for network endian (big-endian)
# 2 ulong (2I) for 4 bytes each seq_num and ack_num
# uchar (B) for 1 byte flags
# pad byte (x) for 1 byte pad
# ushort (H) for 2 bytes checksum
# payload (s) for max 32756 bytes payload
struct_format = '!2IBxH32756s'
# The length of segment
segment_length = 32768
payload_length = 32756
# bitmask for flag
IDX_SYN = 1
IDX_ACK = 4
IDX_FIN = 0
BIT_SYN = 1 << IDX_SYN
BIT_ACK = 1 << IDX_ACK
BIT_FIN = 1 << IDX_FIN
# CRC-16/ARG
# Polynom x^16 + x^15 + x^2 + 1
# only LSB (0b1000000000000101)
# repr in 0x8005, but reversed
crc_poly = int(bin(0x8005)[:1:-1], 2)

def _crc(data) -> int:
    # Calculate CRC-16/ARC
    res = 0
    for byte in data:
        res ^= byte
        for _ in range(8):
            if res & 1:
                res = (res >> 1) ^ crc_poly
            else:
                res >>= 1
    return res


@dataclass
class SegmentFlag(object):
    syn: bool = False
    ack: bool = False
    fin: bool = False

    def test(self, syn=False, ack=False, fin=False) -> bool:
        # Test this class
        return (
            self.syn == syn and
            self.ack == ack and
            self.fin == fin
        )

    @classmethod
    def from_int(cls, flags: int):
        # Convert byte form to this object
        return cls(
            syn=bool(flags & BIT_SYN),
            ack=bool(flags & BIT_ACK),
            fin=bool(flags & BIT_FIN),
        )

    def to_int(self) -> int:
        # Convert this object to flag in byte form
        return (
            (int(self.syn) << IDX_SYN) |
            (int(self.ack) << IDX_ACK) |
            (int(self.fin) << IDX_FIN)
        )


@dataclass
class Segment(object):
    seq_num: int = 0
    ack_num: int = 0
    flags: SegmentFlag = SegmentFlag()
    checksum: int = 0
    payload: bytes = b''

    def __post_init__(self):
        if isinstance(self.flags, int):
            self.flags = SegmentFlag.from_int(self.flags)
        elif not isinstance(self.flags, SegmentFlag):
            raise TypeError('flags must be SegmentFlag or int')

    def _calculate_checksum(self) -> int:
        # Calculate checksum of this object using CRC-16/ARC
        last_checksum = self.checksum
        self.checksum = 0
        segment_check = self.to_bytes(False)
        # process segment_check and pass to result
        res = _crc(segment_check)
        self.checksum = last_checksum
        return res

    # -- Marshalling --
    def to_bytes(self, set_checksum=True) -> bytes:
        # Convert this object to pure bytes
        if set_checksum:
            self.checksum = self._calculate_checksum()
        self.flags = self.flags.to_int()
        res = struct.pack(struct_format, *astuple(self))
        self.flags = SegmentFlag.from_int(self.flags)
        return res

    @classmethod
    def from_bytes(cls, src: bytes) -> Type['Segment'] | None:
        # From pure bytes, unpack() and set into python variable
        if src is not None:
            return Segment(*struct.unpack(struct_format, src))
        return None

    # -- Checksum --
    def valid_checksum(self) -> bool:
        # Use _calculate_checksum() and check integrity of this object
        last_checksum = self.checksum
        self.checksum = 0
        segment_check = self.to_bytes(False)
        # we append reversed checksum
        segment_check = segment_check + last_checksum.to_bytes(2, 'big')[::-1]
        # compute modulo
        res = _crc(segment_check)
        self.checksum = last_checksum
        return res == 0
