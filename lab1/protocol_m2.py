from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport

from playground.network.packet import PacketType

from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, UINT32, BOOL

from playground.network.packet.fieldtypes.attributes import Optional

import random, logging, asyncio, binascii

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


def hashPacket(packet):
    packet.hash = 0
    packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff
    # print("packet.hash", packet.hash)

def checkHash(packet):
    h = packet.hash
    packet.hash = 0
    return h == binascii.crc32(packet.__serialize__()) & 0xffffffff
class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.protocol = 0
        '''
        X and Y are random integers in the range [0, 2^32), where 2^32 is not included.
        '''
        self.x = random.randint(0,2**32)
        self.y = random.randint(0,2**32)
        #self.deserializer = PacketType.Deserializer()
        #HandshakePacket.Deserializer()

    def connection_made(self, transport):
        logger.debug("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        
        self.transport = transport
                
        # Firstly, client send a SYN set to a random value X to server 
        # and the correct hash to the other agent to request a connection.
        if self._mode == "client":
            
            client_packet = HandshakePacket()
            
            client_packet.SYN = self.x
            #client_packet.status = 0
            hashPacket(client_packet)
            transport.write(client_packet.__serialize__())
            print("first success")
        
        #if self._mode == "server":
                    
        '''
        higher_transport = StackingTransport(transport)
        self.higherProtocol().connection_made(higher_transport)
        '''

    def data_received(self, buffer):
        logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
            
        print("data_received begin")
        
        #variable protocol is used to identify whether the connection between client and server is built
        #when protocol ==0, transport handshake_packet
        #else, transport packetType_packet
        # if self.protocol == 0:
        #     self.deserializer = PoopPacketType.Deserializer()
        # else:
        #     self.deserializer = PacketType.Deserializer()
        self.deserializer = PoopPacketType.Deserializer()   
        self.deserializer.update(buffer)
        
        for packet in self.deserializer.nextPackets():
            if self._mode == "server":

                print("mode:  server")
                print("packet:  ",packet)
                if isinstance(packet, HandshakePacket):
                    #Secondly, Upon receiving the HandshakePacket, the server sends back a
                    #packet with ACK set to (X + 1) mod 2^32, SYN set to a random
                    #value Y and status SUCCESS.
                    if packet.status == 0:
                        server_packet = HandshakePacket()
                        server_packet.SYN = self.y
                        server_packet.ACK = (packet.SYN+1)%(2**32) 
                        hashPacket(server_packet)                       
                        self.transport.write(server_packet.__serialize__())
                        print("second success")
                    
                    #Fourthly, The server should check that the ACK received is the correct 
                    # value of (Y + 1) mod 2^32.  If it is correct, then the connection
                    #is considered established on the server side, and full duplex is achieved.  
                    # Else, the server should send a HandshakePacket to the
                    elif packet.ACK == (self.y+1)%(2**32):
                        self.protocol = 1
                        
                        higher_transport = StackingTransport(self.transport)
                        self.higherProtocol().connection_made(higher_transport)
                        #self.higherProtocol().data_received(buffer)
                        self._mode = "higher"
                        print("fourth success")
                    else:
                        server_packet_error = HandshakePacket()
                        server_packet_error.status = 2
                        self.transport.write(server_packet_error.__serialize__())
                        print("fourth fail")
                        
            #Thirdly, Upon receiving the HandshakePacket with status SUCCESS, the
            # client checks if new ACK is (X + 1) mod 2^32.  If it is correct,
            # the client sends back to server a HandshakePacket with ACK set to
            # (Y + 1) mod 2^32 (obtained from SYN of received packet), SYN set
            # to (X + 1) mod 2^32, and status SUCCESS and acknowledge this
            # connection with server. 
            elif self._mode == "client":
                print("mode:  client")
                print("packet:  ",packet)
                if isinstance(packet, HandshakePacket):
                    if packet.ACK == (self.x+1)%(2**32)&checkHash(packet):
                        client_packet2 = HandshakePacket()
                        client_packet2.ACK = (packet.SYN+1)%(2**32)
                        client_packet2.SYN = (packet.ACK)%(2**32)
                        self.protocol = 1
                        hashPacket(client_packet2)
                        self.transport.write(client_packet2.__serialize__())
                        
                        higher_transport = StackingTransport(self.transport)
                        self.higherProtocol().connection_made(higher_transport)
                        #self.higherProtocol().data_received(buffer)
                        self._mode = "higher"
                        print("third success")
                        #Else, the client sends back to server a HandshakePacket with status set to ERROR.
                    else:
                        client_packet_error = HandshakePacket()
                        client_packet_error.status = 2
                        self.transport.write(client_packet_error.__serialize__())
                        print("third fail")
                        
            else:
                print("higher start")
                self.higherProtocol().data_received(buffer)
        
        #self.higherProtocol().data_received(buffer)

        
    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)

PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client")
)

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server")
)
