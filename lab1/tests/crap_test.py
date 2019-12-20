import sys
import os
sys.path.insert(0, os.path.abspath('..'))
import unittest
from connectors.crap_xjm.protocol import *
# from connectors.crap_zqs.protocol import *
from crypto_manager import *
# from connectors.crap_xjm.protocol import *

import asyncio
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG, PRESET_VERBOSE
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream as MockTransport

def print_pkt(pkt):  # try to print packet content
    print("-----------")
    for f in pkt.FIELDS:
        f_name = f[0]
        print(str(f_name) + ": " + str(pkt._fields[f_name]._data))
    print("-----------")
    return

class ListWriter:
    def __init__(self, l):
        self.l = l

    def write(self, data):
        self.l.append(data)


class DummyApplication(asyncio.Protocol):
    def __init__(self):
        self._connection_made_called = 0
        self._connection_lost_called = 0
        self._data                   = []
        self._transport              = None

    def connection_made(self, transport): 
        self._transport               = transport
        self._connection_made_called += 1

    def connection_lost(self, reason=None): 
        self._connection_lost_called += 1

    def data_received(self, data):
        self._data.append(data)
        print('Application data received: ' + data.decode('utf-8'))

    def pop_all_data(self):
        data = b""
        while self._data: 
            data += self._data.pop(0)
        return data

class Test_handshake(unittest.TestCase): 
    def setUp(self):
        self.man    = Crypto_manager()
        self.c_crap = CRAP(mode="client")
        self.s_crap = CRAP(mode="server")

        self.client = DummyApplication()
        self.server = DummyApplication()

        self.c_crap.setHigherProtocol(self.client)
        self.s_crap.setHigherProtocol(self.server)

        self.client_write_storage = []
        self.server_write_storage = []

        self.client_transport = MockTransport(
            ListWriter(self.client_write_storage))
        self.server_transport = MockTransport(
            ListWriter(self.server_write_storage))

        self.deserializer = CrapPacketType.Deserializer()

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

    def test_data_transmit(self):
        test_bytes = b"this is test byte"
        self.test_no_error_handshake()

        self.assertEqual(self.c_crap.peer_iv, self.s_crap.iv)
        self.assertEqual(self.s_crap.peer_iv, self.c_crap.iv)
        self.assertEqual(self.c_crap.dec, self.s_crap.enc)
        self.assertEqual(self.c_crap.enc, self.s_crap.dec)

        # 1. client send, server recv
        self.client._transport.write(test_bytes)
        pkt_1 = self.get_client_last_write_pkt()
        self.s_crap.data_received(pkt_1.__serialize__())

        # 3. server send, client recv
        self.server._transport.write(test_bytes)
        pkt_2 = self.get_server_last_write_pkt()
        self.c_crap.data_received(pkt_2.__serialize__())

    def test_cert_test(self):
        self.s_crap.connection_made(self.server_transport)
        self.c_crap.connection_made(self.client_transport)
        try: 
            # 1. client send hello pkt and challenge pkt
            pkt_1 = self.get_client_last_write_pkt()

            # 2. server recv pkt, send hello ,challenge response and challenge pkt
            # TODO: change client's domain and cert in pkt_1
            self.s_crap.data_received(pkt_1.__serialize__())
            pkt_2 = self.get_server_last_write_pkt()
            if pkt_2.status == 2:
                self.fail("server data recv fail")

            # 3. client recv pkt, generate shared key,send challenge response pkt
            self.c_crap.data_received(pkt_2.__serialize__())
            pkt_3 = self.get_client_last_write_pkt()
            if pkt_3.status == 2:
                self.fail("client data recv fail")

            # 4. server recv pkt, generate shared key
            self.s_crap.data_received(pkt_3.__serialize__())

        except Exception as e: 
            self.fail("fail at no error handshake:"+ e)


    def test_no_error_handshake(self):
        self.s_crap.connection_made(self.server_transport)
        self.c_crap.connection_made(self.client_transport)

        # TODO: change back
        # self.assertTrue(self.s_crap.shared_secret == None)
        # self.assertTrue(self.c_crap.shared_secret == None)

        try: 
            # 1. client send hello pkt and challenge pkt
            pkt_1 = self.get_client_last_write_pkt()
            # print_pkt(pkt_1)

            # 2. server recv pkt, send hello ,challenge response and challenge pkt
            self.s_crap.data_received(pkt_1.__serialize__())
            pkt_2 = self.get_server_last_write_pkt()
            if pkt_2.status == 2:
                self.fail("server data recv fail")
            # print_pkt(pkt_2)

            # 3. client recv pkt, generate shared key,send challenge response pkt
            self.c_crap.data_received(pkt_2.__serialize__())
            # TODO: change back
            # c_shared_secret = self.c_crap.shared_secret
            # self.assertTrue(c_shared_secret != None)
            pkt_3 = self.get_client_last_write_pkt()
            if pkt_3.status == 2:
                self.fail("client data recv fail")
            # print_pkt(pkt_3)

            # 4. server recv pkt, generate shared key
            self.s_crap.data_received(pkt_3.__serialize__())
            # s_shared_secret = self.s_crap.shared_secret
            # self.assertTrue(s_shared_secret != None)
            # print_pkt(pkt_4)

            # self.assertEqual(s_shared_secret, c_shared_secret)
        except Exception as e: 
            self.fail("fail at no error handshake:"+ e)

    def test_no_error_handshake_zsq(self):
        self.s_crap.connection_made(self.server_transport)
        self.c_crap.connection_made(self.client_transport)

        # TODO: change back
        # self.assertTrue(self.s_crap.shared_secret == None)
        # self.assertTrue(self.c_crap.shared_secret == None)

        try: 
            # 1. client send hello pkt and challenge pkt
            pkt_1 = self.get_client_last_write_pkt()
            # print_pkt(pkt_1s)

            # 2. server recv pkt, send hello ,challenge response and challenge pkt
            self.s_crap.data_received(pkt_1.__serialize__())
            pkt_2 = self.get_server_last_write_pkt()
            if pkt_2.status == 2:
                self.fail("server data recv fail")
            # print_pkt(pkt_2)

            # 3. client recv pkt, generate shared key,send challenge response pkt
            self.c_crap.data_received(pkt_2.__serialize__())
            # TODO: change back
            c_shared_secret = self.c_crap.sharedKeyA
            self.assertTrue(c_shared_secret != None)
            pkt_3 = self.get_client_last_write_pkt()
            if pkt_3.status == 2:
                self.fail("client data recv fail")
            print_pkt(pkt_3)

            # 4. server recv pkt, generate shared key
            self.s_crap.data_received(pkt_3.__serialize__())
            s_shared_secret = self.s_crap.sharedKeyB
            self.assertTrue(s_shared_secret != None)
            # print_pkt(pkt_4)

            self.assertEqual(s_shared_secret, c_shared_secret)
        except Exception as e: 
            self.fail("fail at no error handshake:"+ e)

    def test_data_transmit_zsq(self):
        test_bytes = b"this is test byte"
        self.test_no_error_handshake()

        # self.assertEqual(self.c_crap.peer_iv, self.s_crap.iv)
        # self.assertEqual(self.s_crap.peer_iv, self.c_crap.iv)
        # self.assertEqual(self.c_crap.dec_key, self.s_crap.enc_key)
        # self.assertEqual(self.c_crap.enc_key, self.s_crap.dec_key)

        # 1. client send, server recv
        self.client._transport.write(test_bytes)
        pkt_1 = self.get_client_last_write_pkt()
        # pt    = self.man.ASEGCM_dec(self.c_crap.enc_key, self.c_crap.iv, pkt_1.data)
        # self.assertEqual(pt, test_bytes)
        self.s_crap.data_received(pkt_1.__serialize__())

        # 3. server send, client recv
        self.server._transport.write(test_bytes)
        pkt_2 = self.get_server_last_write_pkt()
        self.c_crap.data_received(pkt_2.__serialize__())



if __name__ =="__main__":
    unittest.main()