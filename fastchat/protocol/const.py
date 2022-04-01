import enum
import struct

FLAGS_FORMAT = 'B'
FLAGS_SIZE = struct.calcsize(FLAGS_FORMAT)

DATA_FORMAT = 'Q'
DATA_SIZE = struct.calcsize(DATA_FORMAT)

ID_FORMAT = 'Q'
ID_SIZE = struct.calcsize(ID_FORMAT)

HEADER_FORMAT = f'>{ID_FORMAT}{ID_FORMAT}{DATA_FORMAT}{FLAGS_FORMAT}'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

PUB_KEY_SIZE = 33
SIGN_SIZE = 65


class Flags(enum.Flag):
    SYNC_REQUEST = enum.auto()
    SYNC = enum.auto()
    PING = enum.auto()
    PONG = enum.auto()
    ENCRYPTED = enum.auto()
    FORWARDED = enum.auto()
    MESSAGE = enum.auto()
