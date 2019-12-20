from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
logger = logging.getLogger("playground.__connector__."+__name__)

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, UINT16, UINT32, BUFFER, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

import random,datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
        ("cert", BUFFER({Optional:True}))
    ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]

    
class Crap(StackingProtocol):
    def __init__(self,mode):
        super().__init__()
        print("begin crap")
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        self._stage = "handshake"
            
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
            if self.mode == "server":
                self.data_received_server(packet)
            elif self.mode == "client":
                self.data_received_client(packet)
        
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
    
    # A will also generate a certificate (certA) and will in turn generate a signing ke (signkA).  
    def cert(self):
        #Use RSA to generate a private key
        signk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MD"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team6"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Giotto"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
            ).issuer_name(
                issuer
            ).public_key(
                signk.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
            # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            # Sign our certificate with our private key
            ).sign(signk, hashes.SHA256(), default_backend())
            
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
        client_packet1 = HandshakePacket(status=0, pk=self.pubkA_serial, signature=self.sigA, nonce=self.nonceA, cert=self.certA_serial)
        self.transport.write(client_packet1.__serialize__())
    
    def server_handshake_packet2(self):    
        server_packet2 = HandshakePacket(status=1, pk=self.pubkB_serial, signature=self.sigB, nonce=self.nonceB, cert=self.certB_serial, nonceSignature = self.nonceSignatureB)
        self.transport.write(server_packet2.__serialize__())
            
    def client_handshake_packet3(self):
        client_packet3 = HandshakePacket(status=1, nonceSignature = self.nonceSignatureA)
        self.transport.write(client_packet3.__serialize__())
        
    def data_received_server(self,packet):
        print("data received server")
        if not packet.nonceSignature:
            self.verify_sig(packet)
            #If verification passes, B generates its own ECDH public key (pubkB) and
            #secret key (privkB) using the SECP384R1 curve and default backend.
            self.privkB, self.pubkB, self.pubkB_serial= self.ecdh()
            self.sharedKeyB = self.compute_sharedKey(packet.pk,self.privkB)
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
            self.verify_nonce(packet,self.nonceB)
            #If verificationpasses, the handshake is complete, Else, B drops the connection.
            self._stage = "connected"
            print(self._stage)
    
    def data_received_client(self,packet):
        print("data received client")   
        #Upon receiving the HandshakePacket from B, A verifies the
        #signatures (sigB and nonceSignatureB) using certB.
        self.verify_sig(packet)
        self.verify_nonce(packet,self.nonceA)
        #If verification passes, A can now compute the shared secret, given privkA and pubkB.
        self.sharedKeyA = self.compute_sharedKey(packet.pk,self.privkA)
        #A computes a signature,nonceSignatureA, by signing nonceB with signkA.
        self.nonceSignatureA = self.nonceSig(packet,self.signkA)
        self.client_handshake_packet3()
        print("client send the third handshake packet")
        self._stage = "connected"
        print(self._stage)
    
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
                
    def verify_nonce(self,packet,nonce):
        #get the public key of the cert from the server
        server_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        server_cert_publicKey = server_cert.public_key()
        
        try:
            server_cert_publicKey.verify(
                        packet.nonceSignature,
                        #packet.signature,
                        str(nonceA).encode('ASCII'),
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
    
                    
SecureClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client"),
    lambda: Crap(mode="client")
    )
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server"),
    lambda: Crap(mode="server")
)

