from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional

import binascii
import bisect

logger = logging.getLogger("playground.__connector__." + __name__)


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


# define the higher protocol method
class POOP(StackingTransport):
    def connect_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        self.protocol.send(data)

    def close(self):
        self.protocol.init_close()


class POOPProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        
        self._mode = mode
        # 0 = no connection, 1 = waiting for handshake ack, 2 = connection established, 3 = dying
        self.SYN = None
        self.FIN = None
        self.status = 0
        # --------------------------------------------------------------handshake
        self.last_recv_packet_time = 0  # define the time of the last packet received
        self.check_handshake_timeout_async = None

        # --------------------------------------------------------------datatransfer
        self.send_buffer = []  # define the list to store data
        self.send_window = []
        self.send_window_size = 10
        self.recv_window = []
        self.recv_window_size = 10

        self.send_next = None  # sequence number of next pkt to send
        self.recv_next = None
        self.next_expected_ack = None
        self.seq = randrange(255)

        # --------------------------------------------------------------shutdown
        self.shutdown_wait_start = 0
        # sequence number of last received data pkt that was passed up to the app layer
        self.last_in_order_seq = 0

        # --------------------------------------------------------------function
        self.higher_transport = None
        self.loop = asyncio.get_event_loop()
        self.deserializer = PoopPacketType.Deserializer(errHandler=ErrorHandleClass())

    def connection_made(self, transport):
        logger.debug("{} POOP: connection made".format(self._mode))
        self.transport = transport
        self.last_recv_packet_time = time.time()
        self.loop.create_task(self.check_connection_timeout())

        self.higher_transport = POOP(transport)
        self.higher_transport.connect_protocol(self)

        self.SYN = randrange(2 ** 32)
        self.status = "LISTEN"

        if self._mode == "client":  # client send first packet
            new_hs_pkt = HandshakePacket(SYN=self.SYN, status=0, hash=0)
            new_hs_pkt.hash = binascii.crc32(new_hs_pkt.__serialize__()) & 0xffffffff
            self.transport.write(new_hs_pkt.__serialize__())

            self.check_handshake_timeout_async = self.loop.create_task(self.check_handshake_timeout())
            self.status = 'SYN_SENT'
            # save sended handshake packet
            self.send_buffer.append(new_hs_pkt.__serialize__())

    def data_received(self, buffer):
        logger.debug("{} POOP recv a buffer of size {}".format(self._mode, len(buffer)))
        self.deserializer.update(buffer)

        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if not pkt_type:  # NOTE: not sure if this is necessary
                print("{} POOP error: DEFINITION_IDENTIFIER do not exist")
                return
            logger.debug("{} POOP the pkt name is: {}".format(self._mode, pkt_type))

            if pkt_type == "poop.handshakepacket":
                self.last_recv_packet_time = time.time()
                self.handshake_pkt_recv(pkt)
                continue

            elif pkt_type == "poop.datapacket":
                if self.status == 'FIN_SENT':
                    self.shutdown_ack_recv(pkt)
                self.last_recv_packet_time = time.time()
                self.data_pkt_recv(pkt)
                continue

            elif pkt_type == "poop.shutdownpacket":
                if self.status == 'FIN_SENT':
                    self.shutdown_ack_recv(pkt)
                self.last_recv_packet_time = time.time()
                self.init_shutdown_pkt_recv(pkt)
                continue

            else:
                print("{} POOP error: the recv pkt name: \"{}\" this is unexpected".format(
                    self._mode, pkt_type))
                return

    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)

    # --------------------------------------------------------------handshake
    def handshake_data_recv(self, packet):
        if self.status == "LISTEN":
            if packet.status == 0:
                if packet.SYN:  # server LISTEN and handshake get the packet from the client
                    tmp_packet = HandshakePacket(SYN=packet.SYN, status=packet.status, hash=0)
                    if binascii.crc32(tmp_packet.__serialize__()) & 0xffffffff != packet.hash:
                        return

                    new_handshake_pkt = HandshakePacket(SYN=self.SYN, ACK=packet.SYN + 1, status=1, hash=0)
                    new_handshake_pkt.hash = binascii.crc32(new_handshake_pkt.__serialize__()) & 0xffffffff
                    self.transport.write(new_handshake_pkt.__serialize__())
                    self.status = "SYN_SENT"
                    self.send_buffer.append(new_handshake_pkt.__serialize__())
                else:
                    self.handshake_send_error()
                    return

            elif packet.status == 1:
                self.handshake_send_error()
                return
            else:
                self.handshake_send_error()
                return

        elif self.status == "SYN_SENT":  # server or client already send packet waiting for ack
            if packet.status == 1:
                if packet.ACK:
                    tmp_packet = HandshakePacket(SYN=packet.SYN, ACK=packet.ACK, status=packet.status, hash=0)
                    if binascii.crc32(tmp_packet.__serialize__()) & 0xffffffff != packet.hash:
                        return

                    if packet.ACK == self.SYN + 1:
                        self.send_buffer = []
                        if self._mode == "client":
                            new_handshake_pkt = HandshakePacket(SYN=self.SYN + 1, ACK=packet.SYN + 1, status=1, hash=0)
                            new_handshake_pkt.hash = binascii.crc32(new_handshake_pkt.__serialize__()) & 0xffffffff
                            self.transport.write(new_handshake_pkt.__serialize__())

                            self.send_buffer.append(new_handshake_pkt.__serialize__())
                            self.check_handshake_timeout_async.cancel()
                        # -------------------server/client
                        self.status = "ESTABLISHED"
                        self.send_next = self.SYN
                        self.next_expected_ack = self.SYN
                        self.recv_next = packet.SYN - 1
                        self.last_recv_packet_time = time.time()
                        self.higherProtocol().connection_made(self.higher_transport)
                        logger.debug("{} POOP: handshake success!".format(self._mode))
                    else:
                        self.handshake_send_error()
                        return
                else:
                    self.handshake_send_error()
                    return

            elif packet.status == 0:
                if packet.SYN:
                    tmp_packet = HandshakePacket(SYN=packet.SYN, status=packet.status, hash=0)
                    if binascii.crc32(tmp_packet.__serialize__()) & 0xffffffff != packet.hash:
                        return

                    new_handshake_pkt = HandshakePacket(SYN=self.SYN, ACK=packet.SYN + 1, status=1, hash=0)
                    new_handshake_pkt.hash = binascii.crc32(new_handshake_pkt.__serialize__()) & 0xffffffff
                    self.transport.write(new_handshake_pkt.__serialize__())
                    self.status = "SYN_SENT"
                    self.send_buffer.append(new_handshake_pkt.__serialize__())  # @
                else:
                    self.handshake_send_error()
            else:
                self.handshake_send_error()
                return

        elif packet.status == 2:
            logger.debug("{} POOP: ERROR recv a error pkt ".format(self._mode))
            self.transport.write(self.send_buffer[0])
            return

        elif self.status == "ESTABLISHED":
            logger.debug("recvive a handshake packet when connect ESTABLISHED")
            return

    def handshake_send_error(self):
        print("handshake error!")
        error_pkt = HandshakePacket(status=2)
        error_pkt.hash = binascii.crc32(error_pkt.__serialize__()) & 0xffffffff
        self.transport.write(error_pkt.__serialize__())
        return

    async def check_connection_timeout(self):
        while True:
            if (time.time() - self.last_recv_packet_time) > 300:
                # time out after 5 min
                print("The connection shut down due to 5min limited.")
                self.status = "DYING"
                self.higherProtocol().connection_lost(None)
                self.transport.close()
                return
            await asyncio.sleep(300 - (time.time() - self.last_recv_packet_time))

    async def check_handshake_timeout(self):
        count = 0
        while count < 3:
            if self.status == "ESTABLISHED" or self.status == "FIN_SENT" or self.status == "DYING":
                return

            handshake_pkt = HandshakePacket(SYN=self.SYN, status=0)
            handshake_pkt.hash = binascii.crc32(handshake_pkt.__serialize__()) & 0xffffffff
            self.transport.write(handshake_pkt.__serialize__())
            await asyncio.sleep(1)
            count += 1

    # --------------------------------------------------------------datatransfer
    def send(self, data):
        self.send_buffer += data
        self.data_packets_append()

    def data_packets_append(self):
        while self.send_buffer and len(
                self.send_window) <= self.send_window_size and self.send_next < self.next_expected_ack + self.send_window_size:
            if len(self.send_buffer) >= 15000:
                new_data_packet = DataPacket(seq=self.send_next, data=bytes(self.send_buff[0:15000]), hash=0)
                new_data_packet.hash = binascii.crc32(new_data_packet.__serialize__()) & 0xffffffff
                self.send_buffer = self.send_buffer[15000:]
            else:
                new_data_packet = DataPacket(seq=self.send_next, data=bytes(self.send_buffer[0:len(self.send_buffer)]), hash=0)
                new_data_packet.hash = binascii.crc32(new_data_packet.__serialize__()) & 0xffffffff
                self.send_buffer = []

            if self.recv_next == 2 ** 32:
                self.recv_next = 0
            else:
                self.send_next += 1

            self.send_window.append(new_data_packet)
            self.transport.write(new_data_packet.__serialize__())
            print("Data split has the SEQ=" + str(new_data_packet.seq))
            self.loop.create_task(self.wait_ack_timeout(new_data_packet))

    def data_pkt_recv(self, pkt):
        # Drop if not a datapacket
        if pkt.DEFINITION_IDENTIFIER != "poop.datapacket":
            return

        # If ACK is set, handle ACK
        if pkt.ACK:
            # Check hash, drop if invalid
            pkt_copy = DataPacket(ACK=pkt.ACK, hash=0)
            if binascii.crc32(
                    pkt_copy.__serialize__()) & 0xffffffff != pkt.hash:
                return
            # If ACK matches seq of a pkt in send queue, take off of send queue, and update send queue
            self.send_window[:] = [
                send_pkt for send_pkt in self.send_window
                if send_pkt.seq != pkt.ACK
            ]
            print("IN: ACK=" + str(pkt.ACK))
            if self.send_window:
                self.next_expected_ack = self.send_window[0].seq
            else:
                self.next_expected_ack = pkt.ACK + 1
            self.data_packets_append()
            return

        if pkt.seq <= self.recv_next + self.recv_window_size:
            pkt_copy = DataPacket(seq=pkt.seq, data=pkt.data, hash=0)
            if binascii.crc32(
                    pkt_copy.__serialize__()) & 0xffffffff != pkt.hash:
                return
        else:
            return

        print("IN: SEQ=" + str(pkt.seq))

        ack_pkt = DataPacket(ACK=pkt.seq, hash=0)
        ack_pkt.hash = binascii.crc32(ack_pkt.__serialize__()) & 0xffffffff
        self.transport.write(ack_pkt.__serialize__())
        print("OUT: ACK=" + str(ack_pkt.ACK))

        if pkt.seq < self.recv_next:
            return

        self.recv_window.append(pkt)
        self.recv_window.sort(key=lambda pkt_: pkt_.seq)

        while self.recv_window:
            if self.recv_window[0].seq == self.recv_next:
                self.higherProtocol().data_received(
                    self.recv_window.pop(0).data)
                while self.recv_window:
                    if self.recv_window[0].seq == self.recv_next:
                        self.recv_window.pop(0)
                    else:
                        break
                if self.recv_next == 2 ** 32:
                    self.recv_next = 0
                else:
                    self.recv_next += 1
            else:
                break
        '''
        # MIGHT BE UNNECESSARY
        for pkt in self.recv_queue:
            if pkt.seq < self.recv_next:
                del(pkt)
        '''

    async def wait_ack_timeout(self, this_pkt):
        while self.status == "ESTABLISHED":
            await asyncio.sleep(2)
            for pkt in self.send_window:
                if pkt.seq < this_pkt.seq:
                    continue
                if pkt.seq == this_pkt.seq:
                    self.transport.write(pkt.__serialize__())
                    print('RE: SEQ=' + str(pkt.seq))
                    break
                if pkt.seq > this_pkt.seq:
                    return

    # --------------------------------------------------------------shutdown
    def init_close(self):
        # kill higher protocol
        print('Higher protocol called init_close(). Killing higher protocol.')
        self.higherProtocol().connection_lost(None)
        if not self.send_window:
            self.send_shutdown_pkt()
        else:
            self.loop.create_task(self.shutdown_send_wait())

    def init_shutdown_pkt_recv(self, pkt):
        if pkt.DEFINITION_IDENTIFIER != "poop.shutdownpacket":
            # wrong pkt. Check calling function?
            return
        if not pkt.FIN:
            # missing fields
            print("Missing field(s): FIN")
            return
        if pkt.FIN != self.recv_next:
            # missing packets
            print("Wrong FIN. Missing packets?")
            return
        # send (FIN) ACK data packet and shutdown
        pkt = DataPacket(ACK=pkt.FIN, hash=0)
        pkt.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
        self.transport.write(pkt.__serialize__())
        self.transport.close()
        return

    # this function is called when self already sent a shutdown packet (status == FIN_SENT)
    def shutdown_ack_recv(self, pkt):
        if pkt.DEFINITION_IDENTIFIER == "poop.shutdownpacket":
            # simultaneous shutdown. Shutdown immediately.
            print("Shutdown due to: Simultaneous shutdown")
            self.status = 'DYING'
            self.higherProtocol().connection_lost(None)
            self.transport.close()
            return
        print('Data pkt received while status == FIN_SENT')
        if pkt.DEFINITION_IDENTIFIER != "poop.datapacket" or self.status != 'FIN_SENT':
            # wrong pkt or wrong call (should only be called when self.status == 'FIN_SENT').
            return
        if pkt.seq or pkt.data:
            print('Unexpected field(s) in FACK packet.')
            return
        pkt_copy = DataPacket(ACK=pkt.ACK, hash=0)
        if binascii.crc32(pkt_copy.__serialize__()) & 0xffffffff != pkt.hash:
            print('Wrong hash for FACK pkt, dropping.')
            return
        if pkt.ACK == self.FIN:
            # fin has been ACKed by other agent. Teardown connection.
            print("Shutdown due to: FIN has been acked.")
            self.status = 'DYING'
            self.higherProtocol().connection_lost(None)
            self.transport.close()
        else:
            print("missing ACK field or wrong ACK number.")
            if pkt.ACK:
                print("Pkt type: {} Pkt has ACK={} while protocol has {}".format(
                    pkt.DEFINITION_IDENTIFIER, pkt.ACK, self.FIN))
        return

    # initiate a shutdown by sending the shutdownpacket
    def send_shutdown_pkt(self):
        print('sending shutdown pkt.')
        self.FIN = self.send_next
        pkt = ShutdownPacket(FIN=self.FIN, hash=0)
        pkt.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
        self.transport.write(pkt.__serialize__())
        self.loop.create_task(self.shutdown_timeout_check())
        self.status = 'FIN_SENT'
        return

    async def shutdown_timeout_check(self):
        count = 0
        while count < 2:
            await asyncio.sleep(30)
            if self.status != 'DYING':
                print('Timeout. Resending shutdown pkt.')
                pkt = ShutdownPacket(FIN=self.send_next, hash=0)
                pkt.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
                self.transport.write(pkt.__serialize__())
                count += 1
            else:
                return
        if self.status != 'DYING':
            print("Shutdown due to: timeout.")
            self.status = 'DYING'
            self.higherProtocol().connection_lost(None)
            self.transport.close()
        return

    async def shutdown_send_wait(self):
        # this either send shutdown after all ack received or destroyed by connection_timeout
        while True:
            await asyncio.sleep(1)
            if not self.send_window:
                self.send_shutdown_pkt()
                return
            elif self.status != 'ESTABLISHED':
                return


class ErrorHandleClass():
    def handleException(self, e):
        print(e)


POOPClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOPProtocol(mode="client"))

POOPServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOPProtocol(mode="server"))

