
import asyncio
import base64
import logging
import random
import threading
import typing as tp

from fastchat.protocol import const
from fastchat.protocol.structures import Packet, PacketHeader, SyncData, ForwardData, Peer, MessageData
from fastchat.storage import Storage
from fastchat.utils import cryptogr, generate_id

Address = tp.Tuple[str, int]


class Protocol(asyncio.DatagramProtocol):

    logger = logging.getLogger('protocol')

    def __init__(self, bind_addr: str, port: int):
        self.bind_addr = bind_addr
        self.port = port

        self.transport: tp.Optional[asyncio.DatagramTransport] = None
        self.storage = Storage()
        self.lock = threading.Lock()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Address) -> None:
        while data:
            packet, data = Packet.from_bytes(data)
            self.process_packet(packet, f'{addr[0]}:{addr[1]}')

    def process_packet(self, packet: Packet, address: str):
        if packet.headers.id in self.storage.processed_packets:
            return
        self.storage.processed_packets.add(packet.headers.id)

        if const.Flags.FORWARDED in packet.headers.flags:
            logging.debug('receive FORWARDED from %s', address)

        if peer := self.storage.nets[packet.headers.net_id].peers.get(address):
            self.storage.nets[packet.headers.net_id].active_peers[address] = peer
        else:
            self.send(packet.headers.net_id, address, b'', const.Flags.SYNC_REQUEST)

        if const.Flags.SYNC in packet.headers.flags:
            return self.synchronize_peers(packet.headers.net_id, packet.get_data(self.storage.private_key))

        if const.Flags.SYNC_REQUEST in packet.headers:
            self.sync_with(packet.headers.net_id, address)

        if const.Flags.FORWARDED in packet.headers.flags:
            return self.forward_message(packet.get_data(self.storage.private_key), address)

        if const.Flags.MESSAGE in packet.headers.flags:
            return self.process_message(packet.headers.net_id, packet.get_data(self.storage.private_key), packet.headers.id)

    def synchronize_peers(self, net_id: int, syn_message: SyncData):
        with self.lock:
            new_peers = []

            for peer in syn_message.peers:
                if peer.address in self.storage.nets[net_id].peers:
                    continue

                new_peers.append(peer)
                self.logger.debug('new peer %s', peer)

                self.storage.nets[net_id].peers[peer.address] = peer
                self.send(net_id, peer.address, b'', const.Flags.SYNC_REQUEST | const.Flags.PING)

            if new_peers:
                for address in self.storage.nets[net_id].active_peers:
                    self.send(
                        net_id,
                        address,
                        SyncData(
                            peers=new_peers
                        ).to_bytes(),
                        const.Flags.SYNC
                    )

    def sync_with(self, net_id: int, address: str):
        peers = random.choices(list(self.storage.nets[net_id].peers.values()), k=min(10, len(self.storage.nets[net_id].peers)))
        peers.append(Peer(
            address=f'{self.bind_addr}:{self.port}',
            pub_key=cryptogr.dump_public_key(self.storage.private_key.public_key)
        ))

        self.send(net_id, address, SyncData(peers=peers).to_bytes(), const.Flags.SYNC)

    def forward_message(self, data: ForwardData, address: str):
        next_packet = base64.b64decode(data.packet)
        if not data.next_peer:
            return self.process_packet(Packet.from_bytes(next_packet)[0], address)

        addr, port = data.next_peer.split(':')
        self.transport.sendto(next_packet, (addr, int(port)))

    def process_message(self, net_id: int, data: MessageData, msg_id: int):
        print(f'[MESSAGE] {data.nickname} ({data.sender[:5]}): {data.message}')

        for address in self.storage.nets[net_id].active_peers:
            self.send(net_id, address, data.to_bytes(), const.Flags.MESSAGE, msg_id)

    def send_message(self, net_id: int, message: str):
        data = MessageData.create(self.storage.nickname, message, self.storage.chat_private_key)
        peers = random.choices(list(self.storage.nets[net_id].peers.values()), k=6)

        packet = ForwardData.create(net_id, data, peers)
        addr, port = peers[0].address.split(':')
        self.transport.sendto(packet.to_bytes(), (addr, int(port)))

    def send(self, net_id: int, address: str, data: bytes, flags: const.Flags, msg_id=None):
        data_size = len(data)

        packet = Packet(
            headers=PacketHeader(
                id=msg_id or generate_id(),
                net_id=net_id,
                size=data_size,
                flags=flags,
            ),
            data=data
        )

        addr, port = address.split(':')
        self.transport.sendto(packet.to_bytes(), (addr, int(port)))
