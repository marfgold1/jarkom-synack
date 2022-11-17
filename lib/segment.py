import struct
from dataclasses import astuple, dataclass
from typing import Type

# Constants
# ---------
# Signature for beginning application
signature = b'\x21\x22\x23'
# The length of segment
segment_length = 32768
header_length = 12
payload_length = segment_length - header_length
# The struct_format consist of following format:
# ! for network endian (big-endian)
# 2 ulong (2I) for 4 bytes each seq_num and ack_num
# uchar (B) for 1 byte flags
# pad byte (x) for 1 byte pad
# ushort (H) for 2 bytes checksum
# payload (s) for max 32756 bytes payload
struct_format = f'!2IBxH{payload_length}s'
# bitmask for flag
IDX_SYN = 1
IDX_ACK = 4
IDX_FIN = 0
IDX_META = 7
BIT_SYN = 1 << IDX_SYN
BIT_ACK = 1 << IDX_ACK
BIT_FIN = 1 << IDX_FIN
BIT_META = 1 << IDX_META
# CRC-16/ARG
# Polynom x^16 + x^15 + x^2 + 1
# only LSB (0b1000000000000101)
# repr in 0x8005, but reversed
crc_poly_orig = 0x8005
crc_poly = int(bin(crc_poly_orig)[:1:-1], 2)


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
    meta: bool = False

    def test(self, syn=False, ack=False, fin=False, meta=False) -> bool:
        # Test this class
        return (
            self.syn == syn and
            self.ack == ack and
            self.fin == fin and
            self.meta == meta
        )

    @classmethod
    def from_int(cls, flags: int):
        # Convert byte form to this object
        return cls(
            syn=bool(flags & BIT_SYN),
            ack=bool(flags & BIT_ACK),
            fin=bool(flags & BIT_FIN),
            meta=bool(flags & BIT_META),
        )

    def to_int(self) -> int:
        # Convert this object to flag in byte form
        return (
            (int(self.syn) << IDX_SYN) |
            (int(self.ack) << IDX_ACK) |
            (int(self.fin) << IDX_FIN) |
            (int(self.meta) << IDX_META)
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

    def __str__(self):
        return f'Segment \
            (seq_num={self.seq_num}, \
            ack_num={self.ack_num}, \
            flags={self.flags}, \
            checksum={self.checksum})'

    def is_signature(self) -> bool:
        # Check if this segment is the beginning of application
        return (
            self.flags.test(syn=True) and
            self.payload.rstrip(b'\x00') == signature
        )

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

    def _calculate_checksum(self) -> int:
        # Calculate checksum of this object using CRC-16/ARC
        last_checksum = self.checksum
        self.checksum = 0
        segment_check = self.to_bytes(False)
        # process segment_check and pass to result
        res = _crc(segment_check)
        self.checksum = last_checksum
        return res
