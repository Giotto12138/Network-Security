from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging

import random
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, UINT32, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

import asyncio
import binascii

logger = logging.getLogger("playground.__connector__."+__name__)

#definition of packets
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

# Outline of Interface

# Agents are client and server.  We set the timeout for every step to be 1 second.  
# Our hash mechanism is to set all the values within the packet to the desired values, hash to be 0 then compute the hash to
# be 'binascii.crc32(serialized_packet) & 0xffffffff'.  
# Then set the hash of the packet to this hash.

#hash the packet
def hashPacket(packet):
    packet.hash = 0
    packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff

#check if the hash value is right
def checkHash(packet):
    h = packet.hash
    packet.hash = 0
    return h == binascii.crc32(packet.__serialize__()) & 0xffffffff

# 1. Agents will communicate solely by sending each other packets of the type DataPacket.  
# The only exception to this is when you received a HandshakePacket with SYN and ACK set and the correct hash value, then you need to resend your packet in step 4 of Handshake Protocol.
# 2. The maximum size of any DataPacket shall be 15000 bytes.

class POOPTransport(StackingTransport):
    def __init__(self, transport, seq):
        super().__init__(transport)        
        self.seq = seq
        
        self.confirmed_seqs = {}
        #self.confirmed_seqs = []

    def write(self, data):
        while len(data)>0:
            print("The length of sending data: ",len(data))
            if len(self.send_buffer) >= 15000:
                asyncio.ensure_future(self.myWrite(data[0:15000]))
                data = data[15000:]
            else:
                asyncio.ensure_future(self.myWrite(data))
    
    async def myWrite(self, data):
        self.seq += 1
        seq = self.seq
        #TODO: what the confirmed_seqs is used for
        self.confirmed_seqs[seq] = 1
        while self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
        # while self.protocol._stage != 'closing' and self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            p = DataPacket(seq=seq, data=data)
            hashPacket(p)
            print("MyProtocoLog: send DataPacket seq:", seq, '\n')
            #TODO: lowertransfer is OK?
            self.lowerTransport().write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)

    def close(self):
        print("MyProtocoLog: close", '\n')
        # milestone1 don't _close
        asyncio.ensure_future(self._close())

    async def _close(self):
        self.protocol._stage = 'closing'
        self.seq += 1
        seq = self.seq
        self.confirmed_seqs[seq] = 1
        while self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            p = ShutdownPacket(FIN=seq)
            hashPacket(p)
            print("MyProtocoLog: send ShutdownPacket", seq, '\n')
            self.lowerTransport().write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)
        # print("ddasfijaslfji")
        self.lowerTransport().close()

class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        #There are three stages: handshake, connected, closing
        self._mode = mode
        self._stage = "handshake"
        self.deserializer = PoopPacketType.Deserializer()
        self.received_seqs = {}
        
    #     1.  X and Y are random integers in the range [0, 2^32), where 2^32 is
    #    not included.  HandshakePackets are a POOP Packet Type
    #    responsible for all handshake initiation activities between
    #    agents.
        
        if self._mode == "client":
            self.x = random.randint(0,2**32)
            self.seq = self.x
        elif self._mode == "server":
            self.y = random.randint(0,2**32)
            self.seq = self.y

    def connection_made(self, transport):
        # print("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        # print("transport", transport)

        self.transport = transport
    # The initiating agent needs to send a HandshakePacket with SYN set to a random value X, status set to NOT_STARTED(0), and the correct hash to the other agent to request a connection.
        if self._mode == "client":
            asyncio.ensure_future(self.client_handshake_packet1())
            
    #If any agent never receives the acknowledgement from the other side after timeout or receive a wrong acknowledgement packet(either wrong hash, acknowledge...) or ERROR status, 
    # it will try to resend TWO more times.  
    # If all times failed, it will let go of the connection.        
    #confirmed is used to try three times
    async def client_handshake_packet1(self):
        # print("client_handshake_packet1 fuuuu")
        self.client_handshake_packet1_confirmed = 0
        while self._stage != 'closing' and self.client_handshake_packet1_confirmed >= 0 and self.client_handshake_packet1_confirmed <= 2:
            p = HandshakePacket(SYN=self.x, status=0)
            # print("client_handshake_packet1", p.SYN, p.status)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet1_confirmed += 1
            print("first success")
            await asyncio.sleep(1)

    async def client_handshake_packet2(self, packet):
        self.client_handshake_packet2_confirmed = 0
        while self._stage != 'closing' and self.client_handshake_packet2_confirmed >= 0 and self.client_handshake_packet2_confirmed <= 2:
            # print("client_handshake_packet2")
            p = HandshakePacket(SYN=((self.x+1)%(2**32)), ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet2_confirmed += 1
            print("third success")
            await asyncio.sleep(1)

    async def server_handshake_packet1(self, packet):
        self.server_handshake_packet1_confirmed = 0
        #TODO: whether needs self._stage != connected
        while self._stage != 'closing' and self.server_handshake_packet1_confirmed >= 0 and self.server_handshake_packet1_confirmed <= 2:
            # print("server_handshake_packet1", self.y, ((packet.SYN+1)%(2**32)))
            p = HandshakePacket(SYN=self.y, ACK=((packet.SYN+1)%(2**32)), status=1)
            #print("MyProtocoLog: send HandshakePacket SYN:", p.SYN, "ACK:", p.ACK, '\n')
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.server_handshake_packet1_confirmed += 1
            print("second success")
            await asyncio.sleep(1)
            
        
    def data_received(self, buffer):
        print("data_received", buffer, '\n')
        # print("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))

        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            print(packet)
            if self._mode == "server":
                self.data_received_server(packet)
            elif self._mode == "client":
                self.data_received_client(packet)

    
    def data_received_server(self, packet):
        # print("data_received_server", packet)
        if self._stage == 'handshake':
            if isinstance(packet, HandshakePacket):
                self.server_handshake_packet1_confirmed = -1
                if packet.status == 2: return
                if not checkHash(packet):
                    # print("hash wrong")
                    self.write_error_packet(packet)
                    return
                # print("hash correct", packet)

                # print("pp3", packet.status, packet.ACK, ((self.y+1)%(2**32)))
                # Upon receiving the HandshakePacket with the correct hash, 
                # the receiving agent sends back a packet with ACK set to (X + 1) mod 2^32, SYN set to a random value Y, STATUS sets to SUCCESS, and a hash value.  
                # Else, the receiving agent sends back a packet with status set to ERROR.
                if packet.status == 0:
                    #TODO: whether (if packet.ACK) is necessary
                    if packet.ACK:
                        self.write_error_packet(packet)
                    else:
                        asyncio.ensure_future(self.server_handshake_packet1(packet))
                #The server should check that the ACK received is the correct value of (Y + 1) mod 2^32.  
                # If it is correct, then the connection is considered established on the server side, and full duplex is achieved.  
                # If it is not correct, resend a packet with status ERROR.
                elif packet.status == 1:
                    if packet.ACK == ((self.y+1)%(2**32)):
                        self._stage = 'connected'
                        self.higher_transport = POOPTransport(self.transport, self.seq)
                        self.higherProtocol().connection_made(self.higher_transport)
                    else:
                        self.write_error_packet(packet)
        # elif self._stage == 'connected':
        else:
            self.data_received_duplex(packet)

    # Upon receiving the HandshakePacket, the initiating agent checks if new ACK is (X + 1) mod 2^32 and hash to be correct.  
    # If it is  correct, the initiating agent sends back to receiving agent a HandshakePacket with ACK set to (Y + 1) mod 2^32 (obtained from SYN of received packet), SYN set to (X + 1) mod 2^32, status to be SUCCESS, and a hash, and acknowledge this connection with server.  
    # The connection is considered established on the initiating side.  
    # If it is not correct, the initiating agent sends back packet with status to be ERROR.
    def data_received_client(self, packet):
        print("data_received_client", self._stage, packet)
        if self._stage == 'handshake':
            if isinstance(packet, HandshakePacket):
                #print("MyProtocoLog: Client Received HandshakePacket", packet.status, packet.ACK, ((self.x+1)%(2**32)), '\n')
                self.client_handshake_packet1_confirmed = -1
                if packet.status == 2: return
                if not checkHash(packet):
                    print("MyProtocoLog: hash wrong")
                    # asyncio.ensure_future(self.client_handshake_packet1())
                    self.write_error_packet(packet)
                    return
                if packet.status == 1 and packet.ACK == ((self.x+1)%(2**32)):
                    asyncio.ensure_future(self.client_handshake_packet2(packet))                  
                    self._stage = 'connected'                    
                    self.higher_transport = POOPTransport(self.transport, self.seq)
                    self.higherProtocol().connection_made(self.higher_transport)
                else:
                    self.write_error_packet(packet)
        # elif self._stage == 'connected':
        else:
            self.data_received_duplex(packet)

    def data_received_duplex(self, packet):
        # print("data_received_duplex")
        self.client_handshake_packet2_confirmed = -1
        if isinstance(packet, DataPacket):
            print("DataPacket", packet.ACK, packet.seq, packet.data, '\n')
            if not checkHash(packet):
                # print("hash wrong")
                return
            # print('self.higher_transport.confirmed_seqs', self.higher_transport.confirmed_seqs)
            if packet.ACK:
                if packet.ACK not in self.higher_transport.confirmed_seqs:
                    # self.write_error_packet(packet)
                    pass
                else:
                    print("MyProtocoLog: Received ACK DataPacket", packet.ACK, '\n')
                    # print("packet.ACK correct")
                    self.higher_transport.confirmed_seqs[packet.ACK] = -1
            # elif packet.data:
            else:
                if packet.seq in self.received_seqs:
                    print("MyProtocoLog: Received Old DataPacket", packet.seq, '\n')
                else:
                    print("MyProtocoLog: Received Correct DataPacket", packet.data, '\n')
                    self.higherProtocol().data_received(packet.data)
                self.received_seqs[packet.seq] = True
                
                p = DataPacket(ACK=packet.seq)
                hashPacket(p)
                print("MyProtocoLog: send ACK DataPacket", packet.seq, '\n')
                self.transport.write(p.__serialize__())
        elif isinstance(packet, ShutdownPacket):
            if not checkHash(packet):
                return

            p = DataPacket(ACK=packet.FIN)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.transport.close()

    def write_error_packet(self, packet):
        # print("write_error_packet")
        # p = HandshakePacket(status=2)
        packet.status = 2
        #All ERROR status packets do not need hash.
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

