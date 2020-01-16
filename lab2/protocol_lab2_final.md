# final version protocol for lab2

## Handshake Protocol

The CRAP Handshake protocol MUST function in the following manner.
   The agent that sends the initial packet will be referred to as A, and
   the receiving agent will be referred to as B. For our key exchange 
   protocol, we will use Elliptic Curve Diffie Hellman (ECDH) Key 
   Exchange Protocol. Our signature scheme will use RSA with key size 
   of 2048 for key generation and SHA-256 for the hashing algorithm. 

   We will also be using PEM encoding for keys and certificates. Both
   A and B should have downloaded the root certificate, which will be
   used in certificate authentication. Both parties will send a
   certificate chain, which will be construted similar to the following
   example:
   Party X has access to the root certificate. Party X will need to get
   its own certificate (cert1) signed by the root. If cert1 signs
   another certificate (cert2), and cert2 signs another certificate
   (cert3) and cert3 is the end of the certificate chain, then the
   certificate chain will look like [cert2, cert1] Be aware that the 
   root certificate is not included in this chain, nor is cert3.
   

   1.  A will generate the ECDH parameters using the SECP384R1 curve
       and also the default backend to create the secret key
       (privkA) and public key (pubkA). A will also generate a
       certificate (certA) and will in turn generate a signing key
       (signkA). With this signing key, A will sign pubkA to generate a
       signature (sigA). certA will include A's Playground address in
       the 'Common Name' field and should also be signed by a trusted 
       CA (an intermediate CA whose certificate is signed by the root 
       CA). A will create a list of certificates (certChainA) to be used 
       in certificate authentication. This list will be composed of 
       certificates in the chain leading up to the root certificate, but
       not including the root certificate nor certA (refer to example). 
       A will then generate a nonce of length 32 bits which will be used 
       as a challenge (nonceA). This nonce must be generated randomly. 
       A will send a HandshakePacket to B with status set to  NOT_STARTED, 
       'pk' set to pubkA, 'signature' set to sigA, 'nonce' set to nonceA, 
       and 'cert' set to certA and 'certChain' to certChainA.

   2.  Upon receiving the HandshakePacket, B will verify the signature
       (sigA) received from A. B will also verify that certA is a valid
       certificate (based on the Playground address in certA and the 
       certificate chain certChainA). If verification fails, B sends A a
       HandshakePacket with 'status' ERROR and drops the connection.  If
       verification passes, B generates its own ECDH public key (pubkB) and
       secret key (privkB) using the SECP384R1 curve and default backend.
       B can now also compute the shared secret using pubkA and privkB. B 
       will also generate its own certificate (certB) and will in turn 
       generate its own signing key (signkB). certB will include B's 
       Playground address in the 'Common Name' field and should also be 
       signed by a trusted CA (an intermediate CA whose certificate is 
       signed by the root CA). B will create a list of certificates 
       (certChainB) to be used in certificate authentication. This list 


       will be composed of certificates in the chain leading up to the 
       root certificate, but not including the root certificate nor
       certB (refer to example). With signkB, B will sign pubkB to
       generate a signature (sigB). B will also generate a signature 
       (nonceSignatureB) by signing nonceA with signkB. B will then 
       generate a nonce of length 32 bits which will be used as a 
       challenge (nonceB). This nonce must be generated randomly. B 
       then sends over HandshakePacket with  'status' set to SUCCESS, 
       'pk' set  to pubkB, 'cert' set to certB, 'nonce' set to 
       nonceB, 'nonceSignature' set to nonceSignatureB, 'certChain'
       set to 'certChainB', and 'signature' set to sigB.

   3.  Upon receiving the HandshakePacket from B, A verifies the
       signatures (sigB and nonceSignatureB) using certB. A will also 
       verify that certB is a valid certificate (based on the 
       Playground address in certA and the certificate chain certChainB).

   4.  If A fails to verify the certificate/signatures from B, A sends 
       a HandshakePacket with 'status' set to ERROR to B and drops the
       connection.

   5.  If verification passes, A can now compute the shared secret,
       given privkA and pubkB.  A computes a signature,
       nonceSignatureA, by signing nonceB with signkA. A sends a 
       HandshakePacket to B with 'status' set to SUCCESS and 
       'nonceSignature' set to nonceSignatureA.

   6.  B will now verify nonceSignatureA using certA. If verification
       passes, the handshake is complete, Else, B drops the connection.

##  Data Transmission Protocol
   
   CRAP Data Transmission MUST function in the following manner. The
   agent that acts as the client will referred to as A, and the 
   agent that acts as the server will be referred to as B. Encryption 
   and decryption  will be done using AES-GCM with 128-bit keys and
   96-bit initialization vectors. The hash function used will be SHA-256. 

   1.  At this point, A and B should have a shared pre-master secret.
       Now, they must derive the proper keys and initialization vectors. 
	A will generate the  hash digest of the pre-master secret 
       (hash1). A will then take the first 12 bytes of hash1 and assign 
       that value to A's initialization vector (ivA). A will then assign 
       the second 12 bytes of hash1 to be B's initialization vector (ivB).
      A will now generate the hash digest of hash1 (hash2). A will use 
       the first 16 bytes of hash2 to create A's encryption key (encA). 
       A will now generate the hash digest of hash2 (hash3). A will use
       the first 16 bytes of hash3 to create A's decryption key (decA).

   2.  Given the pre-master secret, B can generate keys and 
       initialization vectors. B will generate the hash digest of
       the pre-master secret (hash1). B will then take the first 12 
       bytes of hash1 and assign that value to A's initialization
       vector (ivA). B will then assign the second 12 bytes of hash1 to
       be B's initialization vector (ivB). B will now generate the 
       hash digest of hash1 (hash2). B will use the first 16 bytes 
       of hash2 to create B's decryption key (decB). B will now 
       generate the hash digest of hash2 (hash3). B will take the 
       first 16 bytes of hash3 to generate B's encryption key (encB).

   3.  Assume A sends data. Upon receiving data at the CRAP layer, A will
       encrypt the data using ivA, encA, and the data itself (encDataA).
       If the function used for encryption requires associated_data, the 
       value will be set to 'None'. A sends a DataPacket to B, with the 
       'data' field set to encDataA. A will now increment ivA by 1 so 
       that A's IV is not reused.

   4.  Upon receiving data, B can decrypt the data using ivA, decB, and
       encDataA. If the function used for decryption requires
       associated_data, the value will be set to 'None'. B will now
       increment ivA by 1 so that A's IV is not reused.


   5.  Assume B sends data. Upon receiving data at the CRAP layer, B will
       encrypt the data using ivB, encB, and the data itself (encDataB).
       If the function used for encryption requires associated_data, the 
       value will be set to 'None'. B sends a DataPacket to A, with the 
       'data' field set to encDataB. B will now increment ivB by 1 so 
       that B's IV is not reused.

   6.  Upon receiving data, A can decrypt the data using ivB, decA, and
       encDataB. If the function used for decryption requires
       associated_data, the value will be set to 'None'. A will now
       increment ivB so that B's IV is not reused.

##  Packet Definitions

   In this section we provide the REQUIRED packet definitions.


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
           ]
