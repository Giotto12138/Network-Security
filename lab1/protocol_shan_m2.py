from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, BUFFER, UINT8, UINT16, UINT32, BOOL
from playground.network.packet.fieldtypes.attributes import Optional
import logging
import random
import asyncio
import binascii
import time

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
            ("error", STRING({Optional: True})),
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


#Hash function and checkHash function
def hashPacket(packet):
    packet.hash = 0
    packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff

def checkHash(packet):
    h = packet.hash
    packet.hash = 0
    result = (h == binascii.crc32(packet.__serialize__()) & 0xffffffff)
    packet.hash = h
    return result

#--------------------- higher transport part -----------------------------
class POOPTransport(StackingTransport):
    
    def __init__(self, protocol, transport, seq):
        print("higher transport begin")
        
        super().__init__(transport)
        self.protocol = protocol
        self.seq = seq
        #use dictionary to record the state of a data packet corresponding to a sequence number
        self.confirmed_seqs = {}

    def write(self, data):
        #The maximum size of any DataPacket shall be 15000 bytes.
        for i in range(0, len(data), 5000):
            asyncio.ensure_future(self.myWrite(data[i:i+5000]))

    def close(self):
        asyncio.ensure_future(self._close())

#------------------------- called functions ------------------------------------------
    async def myWrite(self, data):
        
        seq = self.seq
        self.seq = (self.seq + 1)%(2**32)
        self.confirmed_seqs[seq] = 1
        
        while self.protocol.stage != "closing" and self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            p = DataPacket(seq=seq, data=data)            
            hashPacket(p)        
            print("send data, MyProtocoLog: ","length of data: ", len(data), "seq number: ", seq, "times of sending: ", self.confirmed_seqs[seq], "ack:  ",p.ACK ) 
            
            self.lowerTransport().write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)
            
    async def _close(self):
        print("begin close")
        self.protocol.stage = "closing"
        self.protocol.connection_lost()
        seq = self.seq
        self.FIN = seq
        self.seq (self.seq + 1)%(2**32)
        self.confirmed_seqs[seq] = 1
        while self.confirmed_seqs[seq] >= 1 and self.confirmed_seqs[seq] <= 3:
            p = ShutdownPacket(FIN=seq)
            hashPacket(p)
            self.lowerTransport().write(p.__serialize__())

            self.confirmed_seqs[seq] += 1
            await asyncio.sleep(1)
            
        #TODO: check
        self.lowerTransport().close()
        #self.lowerTransport().connection_lost()
        
# ------------------------------ lower transport part ------------------------------        
#Fot handshake, NOT_STARTED = 0 SUCCESS = 1 ERROR = 2
#For shutdown, SUCCESS = 0 ERROR = 1
#set the timeout for every step to be 1 second 
#If not receives the acknowledgement from the other side after timeout or receive a wrong acknowledgement packet, it will try to resend TWO more times.  
class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        
        self.mode = mode
        #three stages: handshake, connected, closing
        self.stage = "handshake"
        #records if the data packet of a sequence number is received before
        self.received_seqs = {}
        
        self.deserializer = PoopPacketType.Deserializer()
        
        #generate random integers X and Y
        if self.mode == "client":
            self.x = random.randint(0,2**32)
            self.seq = self.x
            print("x:  ",self.x)
        elif self.mode == "server":
            self.y = random.randint(0,2**32)
            self.seq = self.y
            print("y:  ",self.y)
        
    def connection_made(self, transport):
        #logger.debug("{} passthrough connection made. Calling connection made higher.".format(self.mode))

        self.transport = transport
                
        if self.mode == "client":
            asyncio.ensure_future(self.client_handshake_packet1())
            print("client sends the first handshake packet")
            
    def data_received(self, buffer):
        #logger.debug("{} passthrough received a buffer of size {}".format(self.mode, len(buffer)))
        
        print("data_received begin")
        
        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            
            if self.stage == "handshake":
                if isinstance(packet, HandshakePacket):
                    if self.mode == "server":
                        self.handshake_received_server(packet)
                    elif self.mode == "client":
                        self.handshake_received_client(packet)
                        
            if self.stage == "connected":        
                #normal data transmission
                if isinstance(packet, DataPacket):
                    self.data_received_duplex(packet)
                #get a shutdown packet from another side    
                if isinstance(packet,ShutdownPacket):
                    self.shutdown_received(packet)
                    
            if self.stage == "closing":
                #simultaneous shutdown
                if isinstance(packet, ShutdownPacket):
                    self.shutdown_received(packet)
                
                #get the ACK of shutdown packet
                if isinstance(packet, DataPacket):
                    self.shutdown_received(packet)
            
    def connection_lost(self, exc):
        #logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self.mode))
        self.higherProtocol().connection_lost(exc)
    
    # ------------------- called functions ---------------------------------------------   
    
    # --------------------- process handshake received packet --------------------------------- 
    def handshake_received_server(self, packet):
        print("handshake_received_server", self.stage)
        
        if packet.status == 2: 
            print("error packet")
            return
        
        if not checkHash(packet):
            print("hash wrong")
            self.handshake_error()
            return
        #get the first handshake packet from client
        if packet.status == 0:
            if packet.ACK:
                self.handshake_error()
            else:
                asyncio.ensure_future(self.server_handshake_packet1(packet))
                print("server sends the first handshake packet")
        #get the second handshake packet from client        
        if packet.status == 1:
            if packet.ACK == ((self.y+1)%(2**32)):
                self.stage = "connected"
                
                #stop sending client_handshake_packet1
                self.server_handshake_packet1_confirmed = -1
                        
                self.higher_transport = POOPTransport(self, self.transport, self.seq)
                self.higherProtocol().connection_made(self.higher_transport)
            else:
                self.handshake_error()
                
    def handshake_received_client(self, packet):
        print("data_received_client", self.stage)
        
        #stop sending client_handshake_packet1
        self.client_handshake_packet1_confirmed = -1
        
        if packet.status == 2: 
            print("error packet")
            return
        
        if not checkHash(packet):
            print("hash wrong")
            # asyncio.ensure_future(self.client_handshake_packet1())
            self.handshake_error()
            return
        
        if packet.status == 1 and packet.ACK == ((self.x+1)%(2**32)):
            asyncio.ensure_future(self.client_handshake_packet2(packet))                  
            self.stage = "connected"                    
            print("client sends the second handshake packet")
            
            self.higher_transport = POOPTransport(self, self.transport, self.seq)
            self.higherProtocol().connection_made(self.higher_transport)
            
        else:
            self.handshake_error()
            return
    
    #------------------------ send handshake packet part ------------------------------
    async def client_handshake_packet1(self):  
        self.client_handshake_packet1_confirmed = 0
        while self.stage == "handshake" and self.client_handshake_packet1_confirmed >= 0 and self.client_handshake_packet1_confirmed <= 2:
            p = HandshakePacket(SYN=self.x, status=0)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet1_confirmed += 1
            await asyncio.sleep(1)
            
    async def server_handshake_packet1(self, packet):
        self.server_handshake_packet1_confirmed = 0
        while self.stage == "handshake" and self.server_handshake_packet1_confirmed >= 0 and self.server_handshake_packet1_confirmed <= 2:
            p = HandshakePacket(SYN=self.y, ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.server_handshake_packet1_confirmed += 1
            await asyncio.sleep(1)
    
    async def client_handshake_packet2(self, packet):
        self.client_handshake_packet2_confirmed = 0
        while self.stage == "handshake" and self.client_handshake_packet2_confirmed >= 0 and self.client_handshake_packet2_confirmed <= 2:
            p = HandshakePacket(SYN=((self.x+1)%(2**32)), ACK=((packet.SYN+1)%(2**32)), status=1)
            hashPacket(p)
            self.transport.write(p.__serialize__())
            self.client_handshake_packet2_confirmed += 1
            await asyncio.sleep(1)
            
    #--------------------------- data transmission received part -----------------------------        
    def data_received_duplex(self, packet):
        print("data_received_duplex")
        
        #stop sending client_handshake_packet2
        self.client_handshake_packet2_confirmed = -1
        
        if not checkHash(packet):
            print("hash wrong")
            
        if packet.ACK:
            #when this ACK packet is not corresponding to a data packet sent before
            if packet.ACK not in self.higher_transport.confirmed_seqs:
                print("wrong ACK data packet")                    
            #when this ACK packet is corresponding to a data packet sent before
            else:
                print("get an ACK of send data hhhhhhhhhhhhhhhhhhhhh")    
                # mark this sent data packet has been received and stop sending it any more             
                self.higher_transport.confirmed_seqs[packet.ACK] = -1
        
        else:
            if packet.seq in self.received_seqs:
                print("MyProtocoLog: Received Old DataPacket", packet.seq, "\n")
            else:
                print("MyProtocoLog: Received Correct DataPacket", packet.seq, "\n")
                #mark this data packet is received
                self.received_seqs[packet.seq] = True
                self.higherProtocol().data_received(packet.data)
                
            p = DataPacket(ACK=packet.seq)
            print("ACK:   ",p.ACK)
            hashPacket(p)
            print("MyProtocoLog: send ACK DataPacket", packet.seq, '\n')
            self.transport.write(p.__serialize__())
    
    #-------------------------------- shut down process ----------------------------------
    #get a shutdown packet during data transmission
    def shutdown_received(self,packet):
        
        if not checkHash(packet):
            print("hash wrong")
            return
        
        self.stage = "closing"
        
        p = DataPacket(ACK=packet.FIN)
        hashPacket(p)
        print("send FACK KKKKKKKKKKKKKK")
        self.transport.write(p.__serialize__())
        self.connection_lost()
        self.transport.close()
    
    #get a ACK of a sent shutdown packet
    def ack_received(self,packet):
        if not checkHash(packet):
            print("hash wrong")
            return
        
        if packet.ACK == self.higher_transport.FIN:
            # fin has been ACKed by other agent. Teardown connection.
            print("shutdown packet has been acked.")
            self.higher_transport.confirmed_seqs[packet.ACK] = -1
            self.connection_lost()
            self.transport.close()
                
    #---------------------------------- send error packet ----------------------------------------            
    def handshake_error(self):
        print("handshake error!")
        packet = HandshakePacket(status=2)
        self.transport.write(packet.__serialize__())

PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client")
)

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server")
)