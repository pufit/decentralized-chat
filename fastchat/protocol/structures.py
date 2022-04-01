import base64
import pydantic
import struct
import typing as tp

from fastchat.protocol import const
from fastchat.utils import cryptogr, generate_id


class PacketHeader(tp.NamedTuple):
    id: int
    net_id: int
    size: int
    flags: const.Flags

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PacketHeader':
        assert len(data) == const.HEADER_SIZE

        values = struct.unpack(const.HEADER_FORMAT, data)
        # noinspection PyArgumentList
        headers = cls(*values[:-1], const.Flags(values[-1]))
        return headers

    def to_bytes(self) -> bytes:
        return struct.pack(const.HEADER_FORMAT, self.id, self.net_id, self.size, self.flags.value)


class Packet(tp.NamedTuple):
    headers: PacketHeader
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> tp.Tuple['Packet', bytes]:
        assert len(data) >= const.HEADER_SIZE

        headers = PacketHeader.from_bytes(data[:const.HEADER_SIZE])
        packet_data, data = data[const.HEADER_SIZE:const.HEADER_SIZE + headers.size], data[const.HEADER_SIZE + headers.size:]

        # noinspection PyTypeChecker
        return cls(headers, packet_data), data

    def to_bytes(self) -> bytes:
        return self.headers.to_bytes() + self.data

    def get_data(self, key: tp.Optional[cryptogr.PrivateKey] = None):
        data = self.data
        if const.Flags.ENCRYPTED in self.headers.flags:
            if not key:
                raise ValueError('Private key is required for encrypted data')

            data = cryptogr.decrypt_message(self.data, key)

        if const.Flags.SYNC in self.headers.flags:
            return SyncData.from_bytes(data)

        if const.Flags.MESSAGE in self.headers.flags:
            return MessageData.from_bytes(data)

        if const.Flags.FORWARDED in self.headers.flags:
            return ForwardData.from_bytes(data)

        raise ValueError('Could not determine data type')


class BaseData(pydantic.BaseModel):
    def to_bytes(self):
        return self.json().encode()


class Peer(BaseData):
    address: str
    pub_key: str


class SyncData(BaseData):
    peers: tp.List[Peer]

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SyncData':
        return SyncData.parse_raw(data)


class MessageData(BaseData):
    sender: str

    nickname: str
    message: str

    signature: str

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MessageData':
        return MessageData.parse_raw(data)

    @classmethod
    def create(cls, nickname: str, message: str, secret_key: cryptogr.PrivateKey):
        signature = base64.b64encode(secret_key.sign((nickname + message).encode())).decode()
        sender = cryptogr.dump_public_key(secret_key.public_key)

        return cls(
            sender=sender,
            nickname=nickname,
            message=message,
            signature=signature,
        )


class ForwardData(BaseData):
    next_peer: str
    packet: str

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ForwardData':
        return ForwardData.parse_raw(data)

    @classmethod
    def create(cls, net_id: int, message: MessageData, path: tp.List[Peer]) -> 'Packet':
        data = message.to_bytes()

        final_packet = Packet(
            headers=PacketHeader(
                id=generate_id(),
                net_id=net_id,
                size=len(data),
                flags=const.Flags.MESSAGE,
            ),
            data=data,
        )

        prev_peer_address = ''
        for peer in reversed(path):
            data = cryptogr.encrypt_message(
                ForwardData(
                    next_peer=prev_peer_address,
                    packet=base64.b64encode(final_packet.to_bytes())
                ).to_bytes(),
                cryptogr.load_public_key(peer.pub_key)
            )

            final_packet = Packet(
                headers=PacketHeader(
                    id=generate_id(),
                    net_id=net_id,
                    size=len(data),
                    flags=const.Flags.FORWARDED | const.Flags.ENCRYPTED,
                ),
                data=data
            )

            prev_peer_address = peer.address

        return final_packet


if __name__ == '__main__':
    keys = [
        cryptogr.generate_key()
        for _ in range(6)
    ]

    path = [
        Peer(
            address=str(i),
            pub_key=cryptogr.dump_public_key(keys[i].public_key)
        )
        for i in range(6)
    ]

    message = MessageData(
        sender='lol',
        message='kek' * 1000,
        nickname='pufit',
        signature='lol',
    )

    packet = ForwardData.create(111, message, path)
    print(packet)

    for i in range(6):
        packet = Packet.from_bytes(base64.b64decode(packet.get_data(keys[i]).packet))[0]
        print(packet)
