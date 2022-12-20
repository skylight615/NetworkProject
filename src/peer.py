import math
import sys
import os
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
HEADER_LEN = struct.calcsize("HBBHHII")
CHUNK_DATA_SIZE = 512 * 1024
MAX_PAYLOAD = 1380
MAGIC = 52305
TEAM = 27
MAX_SENDING = 4

config = None
ex_output_file = None
ex_received_chunk = dict()
ex_sending_chunkhash = dict()   # 记录可能会发送给其它peer的chunk的hash(收到了谁的whohas)
send_connection = list()        # 记录已经建立的发送连接
receive_connection = dict()     # 记录已经建立的接收连接, (addr_from, chunk_hash)
finished_chunks = list()        # 记录已经下载完成的chunk
ex_downloading_chunkhash = ""

window_size = 1        # 滑动窗口大小,(应该时每次开始传输chunk的时候根据接收和发送双方确定的？)
ssthresh = 64
control_state = 0      # 0是slow start， 1是congestion avoidance
ACK_dict = dict()      # (ack序号:接收次数),用于发送端
file_cache = dict()    # (seq:data),用于接收端,在处理data报文时需要判断是否失序,将失序报文暂存缓存中直到收到缺失报文
finished_dict = dict()  # (),记录接收方已经接受到哪个包了
estimated_RTT, dev_RTT = 0, 0
RTT_TIMEOUT = 100
FIXED_TIMEOUT = 0
TIMEOUT = 100
time_recoder = dict()  #(seq:time)



def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global ex_output_file
    global ex_received_chunk

    ex_output_file = outputfile
    count = 0
    for line in open(chunkfile, 'r'):
        index, datahash_str = line.strip().split(" ")
        count += 1
        ex_received_chunk[datahash_str] = bytes()

        # hex_str to bytes
        datahash = bytes.fromhex(datahash_str)

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte type |1byte team|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
        whohas_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 0, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(datahash)), socket.htonl(0), socket.htonl(0))
        whohas_pkt = whohas_header + datahash

        # Step3: flooding whohas to all peers in peer list
        peer_list = config.peers
        for p in peer_list:
            if int(p[0]) != config.identity:
                sock.sendto(whohas_pkt, (p[1], int(p[2])))
    # ------------------补全chunk---------------------------------
    while len(finished_chunks) != count:
        for chunk_hash in ex_received_chunk.keys():
            if chunk_hash not in finished_chunks:
                datahash = bytes.fromhex(chunk_hash)
                whohas_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 0, socket.htons(HEADER_LEN),
                                            socket.htons(HEADER_LEN + len(datahash)), socket.htonl(0), socket.htonl(0))
                whohas_pkt = whohas_header + datahash

                # Step3: flooding whohas to all peers in peer list
                peer_list = config.peers
                for p in peer_list:
                    if int(p[0]) != config.identity:
                        sock.sendto(whohas_pkt, (p[1], int(p[2])))



def deal_whohas(data, sock, from_addr):
    global ex_sending_chunkhash, send_connection
    # received an WHOHAS pkt
    # see what chunk the sender has
    whohas_chunk_hash = data[:20]
    # bytes to hex_str
    chunkhash_str = bytes.hex(whohas_chunk_hash)
    if len(send_connection) < MAX_SENDING:
        ex_sending_chunkhash[from_addr] = chunkhash_str
        print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks:
            # send back IHAVE pkt
            ihave_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 1, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN + len(whohas_chunk_hash)), socket.htonl(0),
                                       socket.htonl(0))
            ihave_pkt = ihave_header + whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)
    else:
        # send back denied pkt
        denied_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 5, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN), socket.htonl(0),
                                       socket.htonl(0))
        sock.sendto(denied_header, from_addr)


def deal_ihave(data, sock, from_addr):
    # received an IHAVE pkt
    # see what chunk the sender has
    get_chunk_hash = data[:20]
    if get_chunk_hash not in receive_connection.values() and from_addr not in receive_connection.keys():
        receive_connection[from_addr] = get_chunk_hash
        # send back GET pkt
        get_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 2, socket.htons(HEADER_LEN),
                                 socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
        get_pkt = get_header + get_chunk_hash
        sock.sendto(get_pkt, from_addr)


def deal_get(sock, from_addr):
    global send_connection
    if from_addr not in send_connection:
        send_connection.append(from_addr)
    for i in range(window_size):
        # received a GET pkt
        left = i * MAX_PAYLOAD
        right = min((i + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
        chunk_data = config.haschunks[ex_sending_chunkhash[from_addr]][left:right]

        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(i+1), 0)
        # -----------记录发送时间-------------------------------------
        time_recoder[i+1] = (time.time(), from_addr)
        sock.sendto(data_header + chunk_data, from_addr)


def deal_data(data, Seq, sock, from_addr):
    global finished_packetid, file_cache, receive_connection, finished_chunks
    chunk_hash = receive_connection[from_addr]
    if Seq == finished_packetid + 1:
        finished_packetid = Seq
        # received a DATA pkt
        ex_received_chunk[chunk_hash] += data

        while True:
            if (finished_packetid+1) in file_cache:
                ex_received_chunk[chunk_hash] += file_cache[finished_packetid+1]
                finished_packetid += 1
            else:
                break

        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, finished_packetid)
        sock.sendto(ack_pkt, from_addr)

    elif Seq > finished_packetid + 1:
        file_cache[Seq] = data
        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, finished_packetid)
        sock.sendto(ack_pkt, from_addr)

    # see if finished
    if len(ex_received_chunk[chunk_hash]) == CHUNK_DATA_SIZE:
        # finished downloading this chunkdata!
        # dump your received chunk to file in dict form using pickle
        finished_chunks.append(chunk_hash)
        receive_connection.pop(from_addr)
        with open(ex_output_file, "wb") as wf:
            pickle.dump(ex_received_chunk, wf)

        # add to this peer's haschunk:
        config.haschunks[chunk_hash] = ex_received_chunk[chunk_hash]

        # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
        print(f"GOT {ex_output_file}")

        # The following things are just for illustration, you do not need to print out in your design.
        sha1 = hashlib.sha1()
        sha1.update(ex_received_chunk[chunk_hash])
        received_chunkhash_str = sha1.hexdigest()
        print(f"Expected chunkhash: {chunk_hash}")
        print(f"Received chunkhash: {received_chunkhash_str}")
        success = chunk_hash == received_chunkhash_str
        print(f"Successful received: {success}")
        if success:
            print("Congrats! You have completed the example!")
        else:
            print("Example fails. Please check the example files carefully.")


def deal_ack(Ack, sock, from_addr):
    global window_size, ssthresh, control_state, ex_sending_chunkhash, send_connection
    # received an ACK pkt
    ack_num = socket.ntohl(Ack)
    if ack_num in ACK_dict is True:
        ACK_dict[ack_num] += 1
        if ACK_dict[ack_num] >= 3:      #是否要对其进行更改？
            ACK_dict.pop(ack_num)
            ssthresh = max(window_size / 2, 2)
            window_size = 1
            control_state = 0
            left = (ack_num) * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1), 0)
            # -----------记录发送时间-------------------------------------
            time_recoder[ack_num+1] = (time.time(), from_addr)
            sock.sendto(data_header + next_data, from_addr)
    else:
        ACK_dict[ack_num] = 1
        if not control_state:
            window_size += 1
        else:
            window_size = math.floor(window_size + 1 / window_size)  # ????
        if window_size > ssthresh:
            control_state = 1
        if (ack_num + window_size - 1) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # --------------断开连接-----------------------------------
            ex_sending_chunkhash.pop(from_addr)
            send_connection.pop(from_addr)
            print(f"finished sending {ex_sending_chunkhash}")

        else:
            left = (ack_num + window_size - 1) * MAX_PAYLOAD
            right = min((ack_num + window_size) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + window_size), 0)
            # -----------记录发送时间-------------------------------------
            time_recoder[ack_num + window_size] = (time.time(), from_addr)
            sock.sendto(data_header + next_data, from_addr)


def process_inbound_udp(sock):
    global config
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    print("SKELETON CODE CALLED, FILL this!")
    if Type == 0:
        deal_whohas(data, sock, from_addr)
    elif Type == 1:
        deal_ihave(data, sock, from_addr)
    elif Type == 2:
        deal_get(sock, from_addr)
    elif Type == 3:
        # -------------停止检测已经收到包的时间-------------------------
        sample_RTT = time.time() - time_recoder[Seq][0]
        update_RTT_TIMEOUT(sample_RTT)
        time_recoder.pop(Seq)
        deal_data(data, Seq, sock, from_addr)
    elif Type == 4:
        deal_ack(Ack, sock, from_addr)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def process_timeout(sock):
    global window_size, ssthresh, control_state
    current_time = time.time()
    for packetid, info in time_recoder:
        if current_time - info[0] > getTimeout():
            ssthresh = max(window_size/2, 2)
            window_size = 1
            control_state = 0
            left = (packetid-1) * MAX_PAYLOAD
            right = min((packetid) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(packetid), 0)
            # -----------记录发送时间-------------------------------------
            time_recoder[packetid] = (time.time(), info[1])
            sock.sendto(data_header + next_data, info[1])
            break


def update_RTT_TIMEOUT(sample_RTT):
    global estimated_RTT, dev_RTT, RTT_TIMEOUT
    alpha = 0.125
    beta = 0.25
    if estimated_RTT:
        estimated_RTT = (1-alpha)*estimated_RTT + alpha*sample_RTT
    else:
        estimated_RTT = sample_RTT
    if dev_RTT:
        dev_RTT = (1-beta)*dev_RTT + beta*abs(sample_RTT-estimated_RTT)
    else:
        dev_RTT = abs(sample_RTT-estimated_RTT)
    RTT_TIMEOUT = estimated_RTT + 4*dev_RTT


def getTimeout():
    global FIXED_TIMEOUT, RTT_TIMEOUT
    if FIXED_TIMEOUT != 0:
        return FIXED_TIMEOUT
    else:
        return RTT_TIMEOUT


def peer_run(config):
    global time_recoder
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            process_timeout(sock)
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    FIXED_TIMEOUT = config.timeout
    peer_run(config)
