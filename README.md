## Project: P2P File Transfer on UDP With Congestion Control

In this project, you are required to build a reliable peer-to-peer (P2P) file transfer application with congestion control. You are required to implement two major parts in this application:

**I Reliable Data Transfer (RDT) in P2P-like architecture**, including handshaking and transferring of file chunks;

**II Congestion control** for P2P-like file transfer.

Note that this project adopts UDP as the transport layer protocol. Both I and II are implemented in application layer. Part I corresponds a BitTorrent-like protocol, i.e., the P2P file transfer introduced in Section 2.5 on our textbook Computer Networking: A Top Down Approach, 7th Edition available on Sakai. Built upon Part I, Part II is an application layer realization of a TCP-like protocol for P2P file transfer. The ideas of reliable data transfer and congestion control can be found in Sections 3.4–3.7 on our textbook.

### 1 Overview of This Project

This project mimics a BitTorrent file transfer process. In this system, there is one file and multiple peers. Each peer initially owns part of the file. Peers may be directed to download certain chunks from other peers, as in conventional peer-to-peer (P2P) file transfer systems. 

File Segmentation: The file is divided into a set of equal-sized chunks. The size of each chunk is 512 KiB. To distinguish between these chunks, a cryptographic hash with a fixed size of 20 bytes is calculated for each of them. Each chunk can be uniquely identified by its hash value. 

Peers: A peer (client) is a program running with a fixed hostname and port. Initially, each peer (client) holds multiple chunks, which are not necessarily contiguous. The set of chunks owned by a peer is referred as a fragment of the file. Note that the fragments held by different peers may be different and may overlap. 

Packet: A packet is a small portion of a chunk that can fit in the UDP packet data region. There are six different types of packet, which are described detailed in subsection 1.3.

#### Important terms of file

• *.XXX denotes all files with suffix “XXX”. 

• The chunkdata of a chunk is its 512 KiB data bytes. 

• The chunkhash of a chunk is a 20 bytes SHA-1 hash value of its chunkdata.

• *.fragment: serialized dictionary of form {chunkhash: chunkdata}. It is an input file to peer, and it will be automatically 			loaded to dictionary when running a peer. See the example peer (example/dumbsender.py, example/dumbreceiver.py) for 			detail. 

• *.chunkhash: file containing chunkhashes. The master.chunkhash file contains all the chunkhashes of the file, and a 			                     	       downloadxxx.chunkhash file tells a peer the content to download.

#### Meanings of the fields of a header: 

• Magic: The magic number is 52305. It is a constant number used to identify the protocol. 

• Team: Your team index. The index of your team is the first column on the QQ doc, it shall not be 305, which is reserved for testing. 

• Type code: The type of this packet. • Header Length: The header length in byte. • Packet Length: The total length of this packet in byte. 

• Sequence Number: The sequence number for packet, i.e., it counts packets rather than bytes. This field is only valid for DATA packet. For other packets, it shall always be 0. 

• ACK Number: The acknowledgement number. Only valid for ACK packet. For other packets, it shall always be 0.

### 2 Reliable Data Transfer 

In your protocol, you need to implement retransmission triggered by timeout and three duplicate ACKs (i.e., fast retransmit), as in TCP.

#### Handshaking 

Upon receiving a user’s DOWNLOAD command, the peer should gather all the requested chunk data. There will be two procedures: handshaking with other peers and chunk transferring. 

The handshaking procedure consists of three types of messages: WHOHAS, IHAVE, and GET. Specifically, the peer will establish a connection with some of the other peers through a “three-way handshaking” similar to TCP. The “three-way handshaking” can be described as follow: 

1. The peer sends WHOHAS packet to all peers previously known in the network in order to check which peers have the requested chunk data. WHOHAS packet contains a list of chunk hashes indicating which chunks the peer needs. 
2. When other peers receive WHOHAS packet from this peer, they should look into which requested chunks they own respectively. They will send back to this peer with IHAVE packet. Each other peer sends IHAVE packet containing the hash of the requested chunks that it owns. However, if this peer is already sending to  number of other peers at the time when it receives a new WHOHAS, it should send back DENIED. 
3. Once the peer receives all the IHAVE packets from other peers, it knows the chunks owned by other peers. Then, the peer will choose particular peer from which it downloads each requested chunk respectively. It will send GET packet containing the hash of exactly one of the requested chunks to each particular peer for chunk downloading. For example, if the peer decides to download chunk A from peer 1, then it will send GET packet containing the hash of chunk A to peer 1.

#### Congestion Control 

You should design an algorithm in the application layer to control the window size of the sender to implement a congestion control mechanism similar to TCP. The window size, denoted by cwnd, is defined based on the number of packets. For example, a peer with window size of 1 means that it can send at most one unACKed packet at any time. There are two major states: Slow Start and Congestion Avoidance.
