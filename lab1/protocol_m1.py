from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import random
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

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


class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.protocol = 0

    def connection_made(self, transport):
        logger.debug("{} passthrough connection made. Calling connection made higher.".format(self._mode))

#own code
        self.transport = transport
                
        #Firstly, client send a SYN to server(random value from 0 to 254)
        if self._mode == "client":
            
            client_packet = HandshakePacket()
            
            self.syn = random.randint(0,254)
            client_packet.SYN = self.syn
            
            #Firstly, client send a status as NOT STARTED(0)
            client_packet.status = 0

            client_packet.ACK = 5
            client_packet.error = "NULL"
            
            transport.write(client_packet.__serialize__())

            print("first success")
        '''
        if self._mode == "server":
            
        '''
#own code over
        '''
        higher_transport = StackingTransport(transport)
        self.higherProtocol().connection_made(higher_transport)
        '''

    def data_received(self, buffer):
        logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
        
        #own code        
        print("data_received begin")
        
        #variable protocol is used to identify whether the connection between client and server is built
        #when protocol ==0, transport handshake_packet
        #else, transport packetType_packet
        if self.protocol == 0:
            self.deserializer = HandshakePacket.Deserializer()
        else:
            self.deserializer = PacketType.Deserializer()
            #self.buffer.update(buffer)

        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            if self._mode == "server":

                print("ohttttt", packet)
                if isinstance(packet, HandshakePacket):
                    #Secondly, if server receive a packet(status = 0), it send modify SYN to SYN+1, and send
                    #server also sets ACK to 0, and status SUCCESS(1)
                    if packet.status == 0:
                        server_packet = HandshakePacket()
                        server_packet.SYN = packet.SYN+1
                        server_packet.ACK = 0
                        server_packet.status = 1
                        self.transport.write(server_packet.__serialize__())
                        print("second success")
                    
                    #Fourthly, the server checks if ACK is 1
                    #if right, the server acknowledges this connection, sets protocol to 1
                    #and set up a higher layer transport   
                    #if wrong, sends error
                    elif packet.ACK == 1:
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
                        
            #Thirdly, the client checks if SYN == SYN+1
            #if right, it sends ACK as 1 and status SUCCESS(1), it also set protocol to 1, means
            # acknowledge this connection with server and set up a higher layer transport
            #if wrong, it sends status ERROR(2)
            elif self._mode == "client":
                if isinstance(packet, HandshakePacket):
                    if packet.SYN == self.SYN+1:
                        client_packet2 = HandshakePacket()
                        client_packet2.ACK = 1
                        client_packet2.status = 1
                        self.protocol = 1
                        self.transport.write(client_packet2.__serialize__())
                        
                        higher_transport = StackingTransport(self.transport)
                        self.higherProtocol().connection_made(higher_transport)
                        #self.higherProtocol().data_received(buffer)
                        self._mode = "higher"
                        print("third success")
                    else:
                        client_packet_error = HandshakePacket()
                        client_packet_error.status = 2
                        self.transport.write(client_packet_error.__serialize__())
                        print("third fail")
                        
            else:
                print("higher start")
                self.higherProtocol().data_received(buffer)
        #own code over
        
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