from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
logger = logging.getLogger("playground.__connector__."+__name__)

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, UINT16, UINT32, BUFFER, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import Optional

import random,datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .poop.protocol import PassthroughProtocol

#Packet Definition
class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2

    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional:True})),
        ("nonceSignature", BUFFER({Optional:True})),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True})),
        ("certChain", LIST(BUFFER, {Optional:True}))
    ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
        #("signature", BUFFER),
    ]

class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("message", STRING)
    ]

class CrapTransport(StackingTransport):
    def __init__(self, transport, protocol):
        super().__init__(transport)
        self.protocol = protocol

    def write(self, data):
        self.protocol.transport_write(data)

    def close(self):
        self.protocol.transport_close()
    
class Crap(StackingProtocol):
    def __init__(self,mode):
        super().__init__()
        print("begin crap")
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        self.stage = "handshake"
        
        #with open("./team6_signed.cert", mode='rb') as f:
        with open("/home/student_20194/.playground/connectors/crap_shan_m2/team6_signed.cert", mode='rb') as f:
            signed_cert = f.read()
            team6_cert = x509.load_pem_x509_certificate(signed_cert, default_backend())
        self.team6_cert_serial = team6_cert.public_bytes(serialization.Encoding.PEM)
            
    def connection_made(self,transport):
        #logger.debug("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        self.transport = transport
    
        if self.mode == "client":
            self.privkA, self.pubkA, self.pubkA_serial= self.ecdh()
            self.certA_serial, self.signkA = self.cert()
            self.sigA = self.signature(self.pubkA_serial, self.signkA)
    # A will then generate a nonce of length 32 bytes (256 bits) which will be used as a challenge (nonceA). 
    # This nonce must be generated randomly.
            self.nonceA = random.randint(0,2**32)
            self.client_handshake_packet1()
            print("client send the first handshake packet")
                
    def data_received(self, buffer):
        print("data received begin")
        #logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet,DataPacket):
                self.data_received_duplex(packet)
            elif isinstance(packet,HandshakePacket):
                if self.mode == "server":
                    self.data_received_server(packet)
                elif self.mode == "client":
                    self.data_received_client(packet)
            elif isinstance(packet,ErrorPacket):
                print(packet.message)
        
    def connection_lost(self, exc):
        pass
        #logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
                
    # A will generate the ECDH parameters using the SECP384R1 curve
    # and also the default backend to create the secret key(privkA) and public key (pubkA).    
    def ecdh(self):
        privateKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
        publicKey = privateKey.public_key()
        publicKey_serial = publicKey.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
        return privateKey, publicKey, publicKey_serial
    
    # A will also generate a certificate (certA) and will in turn generate a signing key (signkA).  
    def cert(self):
        
        #with open("./end_key.pem", mode='rb') as f:
        with open("/home/student_20194/.playground/connectors/crap_shan_m2/end_key.pem", mode='rb') as f:
            end_key = f.read()
            signk = load_pem_private_key(end_key, b"passphrase", default_backend())
        
        #with open("./end_cert.pem", mode='rb') as f:
        with open("/home/student_20194/.playground/connectors/crap_shan_m2/end_cert.pem", mode='rb') as f:
            end_cert = f.read()
            cert = x509.load_pem_x509_certificate(end_cert, default_backend())
                
        cert_serial = cert.public_bytes(serialization.Encoding.PEM)
        return cert_serial, signk
            
    #With this signing key, A will sign pubkA to generate a signature (sigA).    
    def signature(self,pubKey,signk):        
        sig = signk.sign(
            pubKey,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        return sig
    
    # A will send a HandshakePacket to B with status set to NOT_STARTED, 'pk' set to pubkA, 
    # 'signature' set to sigA, 'nonce' set to nonceA, and 'cert' set to certA.
    def client_handshake_packet1(self):  
        client_packet1 = HandshakePacket(status=0, pk=self.pubkA_serial, signature=self.sigA, nonce=self.nonceA, cert=self.certA_serial, certChain=[self.team6_cert_serial])
        self.transport.write(client_packet1.__serialize__())
    
    def server_handshake_packet2(self):    
        server_packet2 = HandshakePacket(status=1, pk=self.pubkB_serial, signature=self.sigB, nonce=self.nonceB, cert=self.certB_serial, certChain=[self.team6_cert_serial], nonceSignature = self.nonceSignatureB)
        self.transport.write(server_packet2.__serialize__())
            
    def client_handshake_packet3(self):
        client_packet3 = HandshakePacket(status=1, nonceSignature = self.nonceSignatureA)
        self.transport.write(client_packet3.__serialize__())
        
    def data_received_server(self,packet):
        print("data received server")
        if not packet.nonceSignature:
            self.temp_certA = packet.cert
            self.verify_sig(packet)
            #If verification passes, B generates its own ECDH public key (pubkB) and
            #secret key (privkB) using the SECP384R1 curve and default backend.
            self.privkB, self.pubkB, self.pubkB_serial= self.ecdh()
            self.sharedKeyB = self.compute_sharedKey(packet.pk,self.privkB)
            self.sharedKey = self.sharedKeyB
            #B will also generate its own certificate (certB) 
            # and will in turn generate its own signing key (signkB).
            self.certB_serial, self.signkB = self.cert()
            self.sigB = self.signature(self.pubkB_serial, self.signkB)
            self.nonceSignatureB = self.nonceSig(packet, self.signkB)
            #B will then generate a nonce of length 32 bytes (256 bits) 
            # which will be used as a challenge (nonceB). 
            self.nonceB = random.randint(0,2**32)
            self.server_handshake_packet2()
            print("server send the second handshake packet")
        else:
            #B will now verify nonceSignatureA using certA. 
            self.verify_nonce(self.temp_certA,packet.nonceSignature,self.nonceB)
            #If verificationpasses, the handshake is complete, Else, B drops the connection.
            self.stage = "connected"
            print("server",self.stage)
            self.key_iv()
            self.higher_transport = CrapTransport(self.transport, self)
            self.higherProtocol().connection_made(self.higher_transport)
            
    def data_received_client(self,packet):
        print("data received client")   
        #Upon receiving the HandshakePacket from B, A verifies the
        #signatures (sigB and nonceSignatureB) using certB.
        self.verify_sig(packet)
        self.verify_nonce(packet.cert,packet.nonceSignature,self.nonceA)
        #If verification passes, A can now compute the shared secret, given privkA and pubkB.
        self.sharedKeyA = self.compute_sharedKey(packet.pk,self.privkA)
        self.sharedKey = self.sharedKeyA
        #A computes a signature,nonceSignatureA, by signing nonceB with signkA.
        self.nonceSignatureA = self.nonceSig(packet,self.signkA)
        self.client_handshake_packet3()
        print("client send the third handshake packet")
        self.stage = "connected"
        print("client",self.stage)
        self.key_iv()
        self.higher_transport = CrapTransport(self.transport, self)
        self.higherProtocol().connection_made(self.higher_transport)
        
    #Upon receiving the HandshakePacket, B will verify the signature (sigA) received from A.    
    def verify_sig(self,packet):    
        #get the public key of the cert from the client
        client_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        client_cert_publicKey = client_cert.public_key()
        
        try:
            client_cert_publicKey.verify(
                    packet.signature,
                    packet.pk,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()), 
                        salt_length=padding.PSS.MAX_LENGTH
                        ),
                    hashes.SHA256()
                    )
        #If verification fails, B sends A a HandshakePacket with 'status' ERROR and drops the connection. 
        except Exception as e:
            print("client signature wrong, transport closes")
            client_packet_error = HandshakePacket(status=2)
            self.transport.write(client_packet_error.__serialize__())
            self.transport.close()
                
    def verify_nonce(self,cert,nonceSignature,nonce):
        #get the public key of the cert from the server
        server_cert = x509.load_pem_x509_certificate(cert, default_backend())
        server_cert_publicKey = server_cert.public_key()
        
        try:
            server_cert_publicKey.verify(
                        nonceSignature,
                        #packet.signature,
                        str(nonce).encode('ASCII'),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                        )
        #If A fails to verify the certificate from B, A sends a HandshakePacket 
        # with 'status' set to ERROR to B and drops the connection.
        except Exception as e:
            print("server signature wrong, trasport closes")
            packet_error = HandshakePacket(status=2)
            self.transport.write(packet_error.__serialize__())
            self.transport.close()
                
    # B can now also compute the shared secret using pubkA and privkB.        
    def compute_sharedKey(self, pubk,privk):
        #deserialize pubkA
        publicKey = load_pem_public_key(pubk, default_backend())
        
        shared_key = privk.exchange(ec.ECDH(), publicKey) 
        return shared_key
    
    #B will also generate a signature (nonceSignatureB) by signing nonceA with signkB. 
    def nonceSig(self,packet,signk):    
        nonceSignature = signk.sign(
                str(packet.nonce).encode('ASCII'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
        return nonceSignature
    
    def genHash(self,base):
        digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
        digest.update(base)
        return digest.finalize()
    
    def key_iv(self):
        sharedKey = self.sharedKey
        
        hash1 = self.genHash(sharedKey)
        ivA = hash1[:12]
        ivB = hash1[12:24]
        
        hash2 = self.genHash(hash1)
        enc = hash2[:16]
        
        hash3 = self.genHash(hash2)
        dec = hash3[:16]
        
        if self.mode == "client":
            self.iv = ivA
            self.peer_iv = ivB
            self.enc = enc
            self.dec = dec
        else:
            self.iv = ivB
            self.peer_iv = ivA
            self.enc = dec
            self.dec = enc
        
    def increIv(self,iv):
        iv_int = int.from_bytes(iv, "big")
        iv_int = iv_int + 1
        return iv_int.to_bytes(12, "big")
        
    def transport_write(self,data):
        print("transport_write")
        #self.key_iv()
        key = AESGCM.generate_key(bit_length=128)
        encData = AESGCM(self.enc).encrypt(self.iv,data,None)
        self.iv = self.increIv(self.iv)
        dataPacket = DataPacket(data=encData)
        self.transport.write(dataPacket.__serialize__())
        print("crap encrypted and sent data")
        
    def data_received_duplex(self, packet):
        print("data_received_duplex")
        #self.key_iv()
        data = AESGCM(self.dec).decrypt(self.peer_iv, packet.data, None)       
        self.peer_iv = self.increIv(self.peer_iv)
        self.higherProtocol().data_received(data)
        print("crap received and decrypted data")

    def transport_close(self):
        self.higherProtocol().connection_lost(None)
        self.transport.close()
    
            
SecureClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client"),
    lambda: Crap(mode="client")
    )
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server"),
    lambda: Crap(mode="server")
)
