import pydantic
import typing as tp

from collections import defaultdict
from fastchat.utils import cryptogr
from fastchat.protocol.structures import Peer


class Network(pydantic.BaseModel):
    peers: tp.Dict[str, Peer] = {}
    active_peers: tp.Dict[str, Peer] = {}


# TODO!
class Storage:
    nets: tp.DefaultDict[int, Network] = defaultdict(Network)

    processed_packets = set()
    private_key = cryptogr.generate_key()

    chat_private_key = cryptogr.generate_key()

    nickname = 'anon'
