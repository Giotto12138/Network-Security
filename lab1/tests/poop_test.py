import sys
import random
import os
sys.path.insert(0, os.path.abspath('..'))
import unittest
import asyncio
from connectors.poop_xjm.protocol import *
# import inspect
# from connectors.poop_t.protocol import *

from playground.asyncio_lib.testing import TestLoopEx
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG, PRESET_VERBOSE
from playground.network.testing import MockTransportToStorageStream as MockTransport

def print_pkt(pkt):  # try to print packet content
    print("-----------")
    for f in pkt.FIELDS:
        f_name = f[0]
        print(str(f_name) + ": " + str(pkt._fields[f_name]._data))
    print("-----------")
    return

async def timer(t):
    await asyncio.sleep(t)

class ListWriter:
    def __init__(self, l):
        self.l = l

    def write(self, data):
        self.l.append(data)


class DummyApplication(asyncio.Protocol):
    def __init__(self):
        self._connection_made_called = 0
        self._connection_lost_called = 0
        self._data = []
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport
        self._connection_made_called += 1

    def connection_lost(self, reason=None):
        self._connection_lost_called += 1

    def data_received(self, data):
        self._data.append(data)
        asyncio.set_event_loop(TestLoopEx())
        print('Application data received: ' + data.decode('utf-8'))

    def pop_all_data(self):
        data = b""
        while self._data:
            data += self._data.pop(0)
        return data

class Test_POOP_handshake(unittest.TestCase):
    def setUp(self):
        self.c_poop = POOP(mode="client")
        self.s_poop = POOP(mode="server")
        self.c_poop.loop = TestLoopEx()
        self.s_poop.loop = TestLoopEx()

        self.client = DummyApplication()
        self.server = DummyApplication()

        self.c_poop.setHigherProtocol(self.client)
        self.s_poop.setHigherProtocol(self.server)
        # self.c_poop.loop = self.loop
        # self.s_poop.loop = self.loop

        self.client_write_storage = []
        self.server_write_storage = []

        self.client_transport = MockTransport(ListWriter(self.client_write_storage))
        self.server_transport = MockTransport(ListWriter(self.server_write_storage))

        self.s_poop.connection_made(self.server_transport)
        self.c_poop.connection_made(self.client_transport)

        self.deserializer = PoopPacketType.Deserializer()

    def get_client_last_write_pkt(self):
        s = self.client_write_storage
        if not s:
            return None
        else:
            self.deserializer.update(s.pop())
            for pkt in self.deserializer.nextPackets():
                return pkt

    def get_server_last_write_pkt(self):
        s = self.server_write_storage
        if not s:
            return None
        else:
            self.deserializer.update(s.pop())
            for pkt in self.deserializer.nextPackets():
                return pkt

    def get_all_write_pkt(self, storage, error_rate = 0):
        s = storage
        if not s:
            return None
        else:
            while s:
                self.deserializer.update(s.pop())
            pkts = []
            for pkt in self.deserializer.nextPackets():
                if error_rate >0:
                    if random.random() < error_rate:
                        print("Drop packet")
                        continue
                pkts.append(pkt)
            return pkts


    def test_no_error_handshake(self):
        try:
            # # 1. client send SYN
            pkt_1 = self.get_client_last_write_pkt()
            self.assertIsNotNone(pkt_1)
            self.assertTrue(pkt_1.status == 0)
            self.assertTrue(pkt_1.SYN)
            self.assertEqual(self.client._connection_made_called, 0)
            # # 2. server received SYN, send SYN, ACK
            self.s_poop.data_received(pkt_1.__serialize__())
            pkt_2 = self.get_server_last_write_pkt()
            self.assertIsNotNone(pkt_2)
            self.assertTrue(pkt_2.ACK == pkt_1.SYN + 1)
            self.assertTrue(pkt_2.SYN != None)
            self.assertTrue(pkt_2.status == 1)
            self.assertEqual(self.server._connection_made_called, 0)
            # 3. client recv ACK,SYN, establish, send ACK
            self.c_poop.data_received(pkt_2.__serialize__())
            pkt_3 = self.get_client_last_write_pkt()
            self.assertIsNotNone(pkt_3)
            self.assertTrue(pkt_3.ACK == pkt_2.SYN + 1)
            self.assertTrue(pkt_3.status == 1)
            self.assertEqual(self.client._connection_made_called, 1)
            # 4. server recv ACK, establish
            self.s_poop.data_received(pkt_3.__serialize__())
            self.assertEqual(self.server._connection_made_called, 1)
        except Exception as e:
            self.fail("fail at no error handshake:{}".format(e))
    
    def test_no_error_data_transmit(self):
        async def go():
            pkt = self.get_client_last_write_pkt()
            self.s_poop.data_received(pkt.__serialize__())
            pkt = self.get_server_last_write_pkt()
            self.c_poop.data_received(pkt.__serialize__())
            pkt = self.get_client_last_write_pkt()
            self.s_poop.data_received(pkt.__serialize__())

            msg = b"this is bit msg for test"
            # msg = (b"1"*2048)+(b"2"*2048)+(b"3"*2048)+(b"4"*100)

            try:
                # client send 
                self.client._transport.write(msg)
                await timer(0.1)
                print('')

                # server recv
                pkts = self.get_all_write_pkt(self.client_write_storage)
                for pkt in pkts:
                    self.s_poop.data_received(pkt.__serialize__())
                print('')

                # server send 
                self.server._transport.write(msg)
                await timer(0.01)
                print('')

                # client recv
                pkts = self.get_all_write_pkt(self.server_write_storage)
                for pkt in pkts:
                    self.c_poop.data_received(pkt.__serialize__())
                await timer(0.01)
                print('')

                self.assertEqual(self.client.pop_all_data(),self.server.pop_all_data())

            except Exception as e:
                self.fail("fail:{}".format(e))
        asyncio.run(go())

    def test_with_error_data_transmit(self):
        async def go():
            error_rate = 0.1
            pkt = self.get_client_last_write_pkt()
            self.s_poop.data_received(pkt.__serialize__())
            pkt = self.get_server_last_write_pkt()
            self.c_poop.data_received(pkt.__serialize__())
            pkt = self.get_client_last_write_pkt()
            self.s_poop.data_received(pkt.__serialize__())

            # msg = b"this is bit msg for test"
            msg = (b"1"*2048)+(b"2"*2048)+(b"3"*2048)+(b"4"*100)

            try:
                # client send 
                self.client._transport.write(msg)
                await timer(0.1)
                print('')

                # server recv
                pkts = self.get_all_write_pkt(self.client_write_storage, error_rate)
                for pkt in pkts:
                    self.s_poop.data_received(pkt.__serialize__())
                print('')

                # server send 
                self.server._transport.write(msg)
                await timer(0.1)
                print('')

                # client recv
                pkts = self.get_all_write_pkt(self.server_write_storage, error_rate)
                for pkt in pkts:
                    self.c_poop.data_received(pkt.__serialize__())
                await timer(5)
                print('')

                self.assertEqual(self.client.pop_all_data(),self.server.pop_all_data())

            except Exception as e:
                self.fail("fail:{}".format(e))
        asyncio.run(go())

if __name__ == '__main__':
    unittest.main()