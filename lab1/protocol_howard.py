from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging

import random
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, UINT32, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

import asyncio
import binascii

logger = logging.getLogger("playground.__connector__."+__name__)

class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"


class DataPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("seq", UINT32({Optional: True})),
        ("hash", UINT32),
        ("data", BUFFER({Optional: True})),
        ("ACK", UINT32({Optional: True})),
    ]


class HandshakePacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [
        ("SYN", UINT32({Optional: True})),
        ("ACK", UINT32({Optional: True})),
        ("status", UINT8),
        ("hash", UINT32)
    ]

class ShutdownPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"

    SUCCESS = 0
    ERROR = 1

    FIELDS = [
        ("FIN", UINT32),
        ("hash", UINT32)
    ]

def hashPacket(packet):
    packet.hash = 0
    packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff
    # print("packet.hash", packet.hash)

def checkHash(packet):
    h = packet.hash
    packet.hash = 0
    return h == binascii.crc32(packet.__serialize__()) & 0xffffffff


class POOPTransport(StackingTransport):
    def __init__(self, transport, protocol, seq):
        super().__init__(transport)
        self.transport = transport
        self.protocol = protocol
        self.seq = seq
        self.confirmed_seqs = {}

    def write(self, data):
        print("writtttt")
        asyncio.ensure_future(self.myWrite(data))
    
    async def myWrite(self, data):
        self.seq += 1
        seq = self.seq
        self.confirmed_seqs[seq] = 1
        while self.protocol._stage != 'closing' and self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            p = DataPacket(seq=seq, data=data)
            print("myWrite", seq)
            hashPacket(p)
            self.transport.write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)

    def close(self):
        print("closeeee-----------")
        # asyncio.ensure_future(self._close())

    async def _close(self):
        self.protocol._stage = 'closing'
        self.seq += 1
        seq = self.seq
        self.confirmed_seqs[seq] = 0
        while self.confirmed_seqs[seq] >= 0 and self.confirmed_seqs[seq] <= 2:
            p = ShutdownPacket(FIN=seq)
            hashPacket(p)
            self.transport.write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)
        print("ddasfijaslfji")
        self.transport.close()

class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self._stage = 'handshake'
        self.deserializer = PoopPacketType.Deserializer()
        
        if self._mode == "client":
            self.x = random.randint(0,2**32)
            self.seq = self.x
        elif self._mode == "server":
            self.y = random.randint(0,2**32)
            self.seq = self.y

    def connection_made(self, transport):
        print("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        print("transport", transport)

        self.transport = transport
        
        if self._mode == "client":
            asyncio.ensure_future(self.client_handshake_packet1())

    async def client_handshake_packet1(self):
        # print("client_handshake_packet1 fuuuu")
        self.client_handshake_packet1_confirmed = 0
        while self._stage != 'closing' and self.client_handshake_packet1_confirmed >= 0 and self.client_handshake_packet1_confirmed <= 2:
            p = HandshakePacket(SYN=self.x, status=0)
            print("client_handshake_packet1", p.SYN, p.status)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet1_confirmed += 1
            await asyncio.sleep(1)
    
    async def client_handshake_packet2(self, packet):
        self.client_handshake_packet2_confirmed = 0
        while self._stage != 'closing' and self.client_handshake_packet2_confirmed >= 0 and self.client_handshake_packet2_confirmed <= 2:
            # print("client_handshake_packet2")
            p = HandshakePacket(SYN=((self.x+1)%(2**32)), ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet2_confirmed += 1
            await asyncio.sleep(1)

    async def server_handshake_packet1(self, packet):
        self.server_handshake_packet1_confirmed = 0
        while self._stage != 'closing' and self.server_handshake_packet1_confirmed >= 0 and self.server_handshake_packet1_confirmed <= 2:
            # print("server_handshake_packet1")
            p = HandshakePacket(SYN=self.y, ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.server_handshake_packet1_confirmed += 1
            await asyncio.sleep(1)

    def data_received(self, buffer):
        print("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))

        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            if self._mode == "server":
                self.data_received_server(packet)
            elif self._mode == "client":
                self.data_received_client(packet)

    def data_received_server(self, packet):
        print("data_received_server", packet)
        if self._stage == 'handshake':
            if isinstance(packet, HandshakePacket):
                self.server_handshake_packet1_confirmed = -1
                if packet.status == 2: return
                if not checkHash(packet):
                    print("hash wrong")
                    self.write_error_packet(packet)
                    return
                print("hash correct", packet)

                print("pp3", packet.status, packet.ACK, ((self.y+1)%(2**32)))
                if packet.status == 0:
                    if packet.ACK:
                        self.write_error_packet(packet)
                    else:
                        asyncio.ensure_future(self.server_handshake_packet1(packet))

                elif packet.status == 1:
                    if packet.ACK == ((self.y+1)%(2**32)):
                        self._stage = 'connected'
                        self.higher_transport = POOPTransport(self.transport, self, self.seq)
                        self.higherProtocol().connection_made(self.higher_transport)
                    else:
                        self.write_error_packet(packet)
        # elif self._stage == 'connected':
        else:
            self.data_received_duplex(packet)

    def data_received_client(self, packet):
        print("data_received_client", self._stage, packet)
        if self._stage == 'handshake':
            if isinstance(packet, HandshakePacket):
                print("HandshakePacket")
                self.client_handshake_packet1_confirmed = -1
                if packet.status == 2: return
                if not checkHash(packet):
                    print("hash wrong")
                    self.write_error_packet(packet)
                    return
                print("hash correct", packet.status, packet.ACK, ((self.x+1)%(2**32)))
                if packet.status == 1 and packet.ACK == ((self.x+1)%(2**32)):
                    asyncio.ensure_future(self.client_handshake_packet2(packet))

                    self._stage = 'connected'
                    self.higher_transport = POOPTransport(self.transport, self, self.seq)
                    self.higherProtocol().connection_made(self.higher_transport)
                else:
                    self.write_error_packet(packet)
        # elif self._stage == 'connected':
        else:
            self.data_received_duplex(packet)

    def data_received_duplex(self, packet):
        print("data_received_duplex")
        self.client_handshake_packet2_confirmed = -1
        if isinstance(packet, DataPacket):
            print("DataPacket", packet.ACK, packet.seq, packet.data)
            if not checkHash(packet):
                print("hash wrong")
                return
            print('self.higher_transport.confirmed_seqs', self.higher_transport.confirmed_seqs)
            if packet.ACK:
                if packet.ACK not in self.higher_transport.confirmed_seqs:
                    print("packet.ACK wrong")
                    self.write_error_packet(packet)
                else:
                    print("packet.ACK correct")
                    self.higher_transport.confirmed_seqs[packet.ACK] = -1
            # elif packet.data:
            else:
                print("packet.data")
                p = DataPacket(ACK=packet.seq)
                hashPacket(p)
                self.transport.write(p.__serialize__())
                
                self.higherProtocol().data_received(packet.data)
        elif isinstance(packet, ShutdownPacket):
            if not checkHash(packet):
                return

            p = DataPacket(ACK=packet.FIN)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.transport.close()

    def write_error_packet(self, packet):
        print("write_error_packet")
        # p = HandshakePacket(status=2)
        packet.status = 2
        packet.hash = 0
        self.transport.write(packet.__serialize__())
                    
        
    def connection_lost(self, exc):
        self._stage = 'closing'
        # print("connection_lostttt", exc)
        self.higherProtocol().connection_lost(exc)

PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client")
)

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server")
)