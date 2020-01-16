#作为client时，启动shutdown,检查所有ack都收到后启动shutdown
#shutdown功能的完善

from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging

import random
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, UINT32, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

import asyncio
import binascii
import time

logger = logging.getLogger("playground.__connector__."+__name__)

#The definition of packets
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

def hashPacket(packet):
    packet.hash = 0
    packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff

def checkHash(packet):
    h = packet.hash
    packet.hash = 0
    result = (h == binascii.crc32(packet.__serialize__()) & 0xffffffff)
    packet.hash = h
    return result

# 1. Agents will communicate solely by sending each other packets of the type DataPacket.  
# The only exception to this is when you received a HandshakePacket with SYN and ACK set and the correct hash value, then you need to resend your packet in step 4 of Handshake Protocol.
# 2. The maximum size of any DataPacket shall be 15000 bytes.

#this class is for: after handshake, send data
class POOPTransport(StackingTransport):
    
    def __init__(self, protocol, transport, seq):
        print("higher transport begin")
        super().__init__(transport)
        self.protocol = protocol
        self.seq = seq
        #self.confirmed_seqs records how many times this sequence number is sent
        self.confirmed_seqs = {}

    def write(self, data):
        #print("higher transport write")
        #send data of maximum sie 2000
        for i in range(0, len(data), 5000):
            asyncio.ensure_future(self.myWrite(data[i:i+5000]))
        # asyncio.ensure_future(self.myWrite(data))
    
    async def myWrite(self, data):
        #print("higher transport mywrite")
        seq = self.seq
        self.seq = (self.seq + 1)%(2**32)
        self.confirmed_seqs[seq] = 1
        # while self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
        while self.protocol._stage != 'closing' and self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            #await asyncio.sleep(2)
            p = DataPacket(seq=seq, data=data)            
            hashPacket(p)   
            #print("MyProtocoLog: checkHash: ", checkHash(p), "length of data: ", len(data), "seq number: ", seq, "times of sending: ", self.confirmed_seqs[seq], "ack:  ",p.ACK )       
            print("send data, MyProtocoLog: ","length of data: ", len(data), "seq number: ", seq, "times of sending: ", self.confirmed_seqs[seq], "ack:  ",p.ACK ) 
            #TODO: whether lowerTransport is right
            #self.transport.write(p.__serialize__())
            self.lowerTransport().write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            #await asyncio.sleep(2)
            await asyncio.sleep(1)

    def close(self):
        # print("MyProtocoLog: close", '\n')
        #time.sleep(2)
        asyncio.ensure_future(self._close())

    async def _close(self):
        print("begin close")
        self.protocol._stage = 'closing'
        seq = self.seq
        self.seq += 1
        self.confirmed_seqs[seq] = 1
        while self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            p = ShutdownPacket(FIN=seq)
            hashPacket(p)
            #self.transport.write(p.__serialize__())
            self.lowerTransport().write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)
        #self.transport.write(p.__serialize__())
        self.lowerTransport().close()

class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self._stage = 'handshake'
        self.deserializer = PoopPacketType.Deserializer()
        self.received_seqs = {}
        
        if self._mode == "client":
            self.x = random.randint(0,2**32)
            self.seq = self.x
            print("x:  ",self.x)
        elif self._mode == "server":
            self.y = random.randint(0,2**32)
            self.seq = self.y
            print("y:  ",self.y)

    def connection_made(self, transport):
        # print("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        self.transport = transport
        
        # self.higher_transport = POOPTransport(self, self.transport, self.seq)
        # self.higherProtocol().connection_made(self.higher_transport)
        
        if self._mode == "client":
            asyncio.ensure_future(self.client_handshake_packet1())

    async def client_handshake_packet1(self):
        self.client_handshake_packet1_confirmed = 0
        while self._stage != 'closing' and self.client_handshake_packet1_confirmed >= 0 and self.client_handshake_packet1_confirmed <= 2:
            p = HandshakePacket(SYN=self.x, status=0)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet1_confirmed += 1
            print("first success")
            await asyncio.sleep(1)
    
    async def client_handshake_packet2(self, packet):
        self.client_handshake_packet2_confirmed = 0
        while self._stage != 'closing' and self.client_handshake_packet2_confirmed >= 0 and self.client_handshake_packet2_confirmed <= 2:
            p = HandshakePacket(SYN=((self.x+1)%(2**32)), ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet2_confirmed += 1
            print("third success")
            await asyncio.sleep(1)

    async def server_handshake_packet1(self, packet):
        self.server_handshake_packet1_confirmed = 0
        while self._stage != 'closing' and self.server_handshake_packet1_confirmed >= 0 and self.server_handshake_packet1_confirmed <= 2:
            p = HandshakePacket(SYN=self.y, ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.server_handshake_packet1_confirmed += 1
            print("second success")
            await asyncio.sleep(1)

    def data_received(self, buffer):
        #print("data_received", buffer, '\n')
        print("data_received")
        # print("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))

        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            print("packet:   ",packet)
            if self._mode == "server":
                self.data_received_server(packet)
            elif self._mode == "client":
                self.data_received_client(packet)

    def data_received_server(self, packet):
        print("data_received_server", self._stage, packet)
        if self._stage == 'handshake':
            if isinstance(packet, HandshakePacket):
                self.server_handshake_packet1_confirmed = -1
                if packet.status == 2: 
                    return
                    print("error packet")
                if not checkHash(packet):
                    print("hash wrong")
                    self.write_error_packet(packet)
                    return
                # Upon receiving the HandshakePacket with the correct hash, 
                # the receiving agent sends back a packet with ACK set to (X + 1) mod 2^32, SYN set to a random value Y, STATUS sets to SUCCESS, and a hash value.  
                # Else, the receiving agent sends back a packet with status set to ERROR.
                if packet.status == 0:
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
                        #self.higher_transport = POOPTransport(self.transport, self.seq)               
                        self.higher_transport = POOPTransport(self, self.transport, self.seq)
                        self.higherProtocol().connection_made(self.higher_transport)
                    else:
                        self.write_error_packet(packet)
        #elif self._stage == 'connected':
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
                if packet.status == 2: 
                    print("error packet")
                    return
                if not checkHash(packet):
                    print("MyProtocoLog: hash wrong")
                    # asyncio.ensure_future(self.client_handshake_packet1())
                    self.write_error_packet(packet)
                    return
                if packet.status == 1 and packet.ACK == ((self.x+1)%(2**32)):
                    asyncio.ensure_future(self.client_handshake_packet2(packet))                  
                    self._stage = 'connected'                    
                    #self.higher_transport = POOPTransport(self.transport, self.seq)
                    self.higher_transport = POOPTransport(self, self.transport, self.seq)
                    self.higherProtocol().connection_made(self.higher_transport)
                else:
                    self.write_error_packet(packet)
        #elif self._stage == 'connected':
        else:
            self.data_received_duplex(packet)

    def data_received_duplex(self, packet):
        print("data_received_duplex")
        self.client_handshake_packet2_confirmed = -1
        if isinstance(packet, DataPacket):
            # print("DataPacket", packet.ACK, packet.seq, packet.data, '\n')
            if not checkHash(packet):
                print("hash wrong")
                return
            #if it is an ACK packet
            if packet.ACK:
                #TODO: whether the logic of following lines is right
                #when this ack has been received before
                if packet.ACK not in self.higher_transport.confirmed_seqs:                    
                    pass
                #when this ack has not been received before, mark it as received
                else:
                    print("get an ACK of send data hhhhhhhhhhhhhhhhhhhhh")    
                    # mark this packet has been received             
                    self.higher_transport.confirmed_seqs[packet.ACK] = -1
                    
            #if it is not an ACK packet
            #TODO: whether the logic of following lines is right
            else:
                if packet.seq in self.received_seqs:
                    pass
                    # print("MyProtocoLog: Received Old DataPacket", packet.seq, '\n')
                else:
                    # print("MyProtocoLog: Received Correct DataPacket", packet.seq, '\n')
                    self.higherProtocol().data_received(packet.data)
                    self.received_seqs[packet.seq] = True
                
                p = DataPacket(ACK=packet.seq)
                print("ACK:   ",p.ACK)
                hashPacket(p)
                # print("MyProtocoLog: send ACK DataPacket", packet.seq, '\n')
                self.transport.write(p.__serialize__())
        elif isinstance(packet, ShutdownPacket):
            if not checkHash(packet):
                print("hash wrong")
                return

            p = DataPacket(ACK=packet.FIN)
            hashPacket(p)
            print("send FACK KKKKKKKKKKKKKK")
            self.transport.write(p.__serialize__())
            self.transport.close()
        
        #TODO: data transfer时收到handshake packet问题
        elif isinstance(packet, HandshakePacket):
            print("A handshake packet appears in data transfer !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            return
        

    def write_error_packet(self, packet):
        print("write_error_packet")
        # p = HandshakePacket(status=2)
        packet.status = 2
        packet.hash = 0
        packet = hashPacket(packet)
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

