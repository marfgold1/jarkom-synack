from dataclasses import dataclass


@dataclass
class Config(object):
    WINDOW_SIZE: int = 10
    TIMEOUT_HANDSHAKE: float = 5.0
    TIMEOUT_FILE: float = 5.0
    MAX_RETRY: int = 5
    VERBOSE: int = 0


config = Config()
