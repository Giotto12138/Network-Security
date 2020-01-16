# protocol for lab1 final version

## Outline of Interface  
Agents are client and server.  We set the timeout for every step to
   be 1 second.  Our hash mechanism is to set all the values within the
   packet to the desired values, hash to be 0 then compute the hash to
   be 'binascii.crc32(serialized_packet) & 0xffffffff'.  Then set the
   hash of the packet to this hash.

## Implementation

### Handshake Protocol
The Playground Handshake protocol MUST function in the following
   manner.  The handshake will be communicated according to the Data
   Transfer protocol.  The agent that sends the initial packet will be
   referred to as the "initiating agent", and the agent receiving the
   first packet will be referred to as the "receiving agent".

   1.  X and Y are random integers in the range [0, 2^32), where 2^32 is
       not included.  HandshakePackets are a POOP Packet Type
       responsible for all handshake initiation activities between
       agents.

   2.  The initiating agent needs to send a HandshakePacket with SYN set
       to a random value X, status set to NOT_STARTED, and the correct
       hash to the other agent to request a connection.

   3.  Upon receiving the HandshakePacket with the correct hash, the
       receiving agent sends back a packet with ACK set to (X + 1) mod
       2^32, SYN set to a random value Y, STATUS sets to SUCCESS, and a
       hash value.  Else, the receiving agent sends back a packet with
       status set to ERROR.

   4.  Upon receiving the HandshakePacket, the initiating agent checks
       if new ACK is (X + 1) mod 2^32 and hash to be correct.  If it is

       correct, the initiating agent sends back to receiving agent a
       HandshakePacket with ACK set to (Y + 1) mod 2^32 (obtained from
       SYN of received packet), SYN set to (X + 1) mod 2^32, status to
       be SUCCESS, and a hash, and acknowledge this connection with
       server.  The connection is considered established on the
       initiating side.  If it is not correct, the initiating agent
       sends back packet with status to be ERROR.

   5.  The server should check that the ACK received is the correct
       value of (Y + 1) mod 2^32.  If it is correct, then the connection
       is considered established on the server side, and full duplex is
       achieved.  If it is not correct, resend a packet with status
       ERROR.

   6.  All ERROR status packets do not need hash.

   7.  If any agent never receives the acknowledgement from the other
       side after timeout or receive a wrong acknowledgement packet
       (either wrong hash, acknowledge...) or ERROR status, it will try
       to resend TWO more times.  If all times failed, it will let go of
       the connection.

   8.  Packets of a type other than HandShake packet should not be sent
       beyond the handshake layer until the handshake has been
       completed.

### Data Transfer
 1.   Agents will communicate solely by sending each other packets of
        the type DataPacket.  The only exception to this is when you
        received a HandshakePacket with SYN and ACK set and the correct
        hash value, then you need to resend your packet in step 4 of
        Handshake Protocol.

   1.   The maximum size of any DataPacket shall be 15000 bytes.

   2.   The data field should be bytes representing all or part of
        another packet.

   3.   Multiple DataPacket packets with data fields that are identical
        to the data fields of previously sent DataPacket packets may be
        sent.

  1.   No bytes representing full or partial packets may be sent other
        than as part of a data field that is identical to the one in
        which they were originally sent.


   4.   All agents set the sequence number on the first packet they send
        to be the random value they generated during the course of the
        Handshake Protocol.

   5.   Sequence numbers will subsequently be assigned according to the
        following rules.  If the data contained in the DataPacket has
        not yet been sent, the sequence number should be 1 greater than
        the greatest sequence number previously sent, mod 2^32.  If the
        data contained in the DataPacket has already been sent
        previously, and is being resent, the sequence number should be
        set to the sequence number of the DataPacket used to send the
        data the first time it was sent.

   6.   Once an agent receives a DataPacket packet, and has confirmed
        that the hash matches the data, it must send back a DataPacket
        with an empty data and seq field, and ACK set to the sequence
        number of the packet it received

   7.   Only one of "ACK" and "data" must be set.  If "ACK" is set,
        "data" and "seq" will be ignored, and if "data" is set, "ACK"
        will be ignored
        

   8.   Once an agent receives confirmation of receipt of a DataPacket
        packet it sent, it can assume that the other agent has received
        the data contained therein
        

   9.   If no confirmation of receipt of a DataPacket is received within
        an implementation-specified period, the agent should resend the
        DataPacket.
        

   10.  Each agent shall be considered responsible for every packet it
        has acknowledged receipt of at any point

### Shutdown Protocol
The Playground shutdown protocol MUST function in the following
   manner.  The shutdown will be communicated according to the Data
   Transfer protocol.

   1.  Assuming two agents to be A1 and A2.  WLOG, A1 wants to
       initialize shutdown protocol.

   2.  After checking that it has received all ACKs from A2, A1 sends a
       ShutdownPacket with FIN as the next sequence number and correct
       hash.  If A1 does not receive any FIN acknowledgement after
       timeout, A1 resends the ShutdownPacket 2 more times.  If A1 never
       hears back from A2, it will shut down by itself.   

3.  Upon receiving the ShutdownPacket with correct FIN, A2 sends ONE
       DataPacket with ACK as the packet's FIN received and hash.  A2
       will shut down at this step.  This step is similar with the
       scenario for A1 already sent FIN and received another FIN, which
       will guarantee shutdown for A1.

   4.  Upon receiving the DataPacket with correct ACK and hash, A1 will
       shut down.   

## Packet Definitions
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
