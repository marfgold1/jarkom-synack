import argparse
import os
import pathlib
import struct
from typing import NamedTuple

from lib.segment import payload_length

metadata_header_length = 8
metadata_format = f'!2I{payload_length-metadata_header_length}s'


class DirectoryValidator(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = pathlib.Path(values).resolve()
        if not os.path.isdir(values):
            raise argparse.ArgumentError(
                self,
                f'{values} is not a valid directory',
            )
        setattr(namespace, self.dest, values)


class FileValidator(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = pathlib.Path(values).resolve()
        if not os.path.isfile(values):
            raise argparse.ArgumentError(
                self,
                f'{values} is not a valid file',
            )
        setattr(namespace, self.dest, values)


class Metadata(NamedTuple):
    file_size: int
    segment_length: int
    file_name: str

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Metadata':
        filesize, segment_length, filename = struct.unpack(
            metadata_format,
            data,
        )
        return cls(
            filesize,
            segment_length,
            filename.rstrip(b'\x00').decode(),
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            metadata_format,
            self.file_size,
            self.segment_length,
            self.file_name.encode(),
        )
