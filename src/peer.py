import math
import sys
import os
import select
import traceback
import matplotlib.pyplot as plt
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
MAX_PAYLOAD = 1384
MAGIC = 52305
TEAM = 27
MAX_SENDING = 4

config = None
ex_output_file = None
ex_received_chunk = dict()
ex_sending_chunkhash = dict()   # 记录可能会发送给其它peer的chunk的hash(收到了谁的whohas)
receive_connection = dict()     # 记录已经建立的接收连接, (addr_from, chunk_hash)
finished_chunks = list()        # 记录已经下载完成的chunk
count = 0                       # 记录下载指令应该接收到多少chunk

window_size = dict()        # 滑动窗口大小,(应该时每次开始传输chunk的时候根据接收和发送双方确定的？)
ssthresh = dict()
control_state = dict()     # 0是slow start， 1是congestion avoidance
congestion_avoidance_count = dict()
ACK_dict = dict()      # (ack序号:接收次数),用于发送端
file_cache = dict()    # (from_address : dict(packetid : data)), 用于接受方
finished_dict = dict()  # (from_address, finish_num),记录接收方已经接受到哪个包了,用于接受方
finished_send_dict = dict()  # (from_address:packetid), 用于发送方记录给确定的某个接收方传输的最新报文编号
estimated_RTT, dev_RTT = 0, 0
RTT_TIMEOUT = 100
FIXED_TIMEOUT = 0
CLOSED_TIME = 60
IHAVE_TIME = 10
time_recoder = dict()  #(seq:time)
ihave_recoder = dict()
cwnd_list = list()
die_recoder = dict()       #(from_address:time) check if die in reciever


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global ex_output_file, ex_received_chunk, count

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


def complement_integrity(sock):
    global ex_received_chunk
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
    global ex_sending_chunkhash
    # received an WHOHAS pkt
    # see what chunk the sender has
    whohas_chunk_hash = data[:20]
    # bytes to hex_str
    chunkhash_str = bytes.hex(whohas_chunk_hash)
    if len(ex_sending_chunkhash) < MAX_SENDING:
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
    global ihave_recoder
    get_chunk_hash = data[:20]
    if get_chunk_hash not in receive_connection.values() and from_addr not in receive_connection.keys():
        receive_connection[from_addr] = get_chunk_hash
        # send back GET pkt
        get_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 2, socket.htons(HEADER_LEN),
                                 socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
        get_pkt = get_header + get_chunk_hash
        sock.sendto(get_pkt, from_addr)
        ihave_recoder[from_addr] = time.time()


def deal_get(data, sock, from_addr):
    global ex_sending_chunkhash
    chunk_hash = data[:20]
    time_recoder[from_addr] = dict()
    if from_addr not in ACK_dict:
        ACK_dict[from_addr] = dict()
    if from_addr not in ex_sending_chunkhash.keys():
        ex_sending_chunkhash[from_addr] = bytes.hex(chunk_hash)
    if from_addr not in finished_send_dict:
        window_size[from_addr] = 1
        ssthresh[from_addr] = 64
        control_state[from_addr] = 0
        congestion_avoidance_count[from_addr] = 0
        finished_send_dict[from_addr] = 1
    for i in range(window_size[from_addr]):
        # received a GET pkt
        left = i * MAX_PAYLOAD
        right = min((i + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
        chunk_data = config.haschunks[ex_sending_chunkhash[from_addr]][left:right]
        if right == CHUNK_DATA_SIZE:
            break

        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(i+1), 0)
        # -----------记录发送时间-------------------------------------
        time_recoder[from_addr][i+1] = (time.time(), from_addr)
        sock.sendto(data_header + chunk_data, from_addr)


def deal_data(data, Seq, sock, from_addr):
    global finished_dict, file_cache, receive_connection, finished_chunks
    chunk_hash = receive_connection[from_addr]
    die_recoder[from_addr] = time.time()
    if from_addr in ihave_recoder:
        ihave_recoder.pop(from_addr)
    if from_addr not in finished_dict:
        finished_dict[from_addr] = 0
    if from_addr not in file_cache:
        file_cache[from_addr] = dict()
    # old_finish = finished_dict[from_addr]
    # sendnum = 0
    if Seq == finished_dict[from_addr] + 1:
        finished_dict[from_addr] = Seq
        # received a DATA pkt
        ex_received_chunk[bytes.hex(chunk_hash)] += data

        while True:
            if (finished_dict[from_addr]+1) in file_cache[from_addr]:
                ex_received_chunk[bytes.hex(chunk_hash)] += file_cache[from_addr][finished_dict[from_addr]+1]
                finished_dict[from_addr] += 1
            else:
                break

        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, socket.htonl(finished_dict[from_addr]))
        sock.sendto(ack_pkt, from_addr)
        sendnum = finished_dict[from_addr]

    elif Seq > finished_dict[from_addr] + 1:
        file_cache[from_addr][Seq] = data
        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, socket.htonl(finished_dict[from_addr]))
        sock.sendto(ack_pkt, from_addr)
        sendnum = finished_dict[from_addr]
    # see if finished
    if len(ex_received_chunk[bytes.hex(chunk_hash)]) == CHUNK_DATA_SIZE:
        file_cache.pop(from_addr)
        die_recoder.pop(from_addr)
        # finished downloading this chunkdata!
        # dump your received chunk to file in dict form using pickle
        finished_chunks.append(chunk_hash)
        receive_connection.pop(from_addr)


        if len(receive_connection)==0:
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)

        # add to this peer's haschunk:
        config.haschunks[chunk_hash] = ex_received_chunk[bytes.hex(chunk_hash)]

        # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
        print(f"GOT {ex_output_file}")

        # The following things are just for illustration, you do not need to print out in your design.
        sha1 = hashlib.sha1()
        sha1.update(ex_received_chunk[bytes.hex(chunk_hash)])
        received_chunkhash_str = sha1.hexdigest()
        print(f"Expected chunkhash: {chunk_hash}")
        print(f"Received chunkhash: {received_chunkhash_str}")
        success = bytes.hex(chunk_hash) == received_chunkhash_str
        print(f"Successful received: {success}")
        if success:
            print("Congrats! You have completed the example!")
        else:
            print("Example fails. Please check the example files carefully.")


def deal_ack(Ack, sock, from_addr):
    global window_size, ssthresh, control_state, ex_sending_chunkhash, congestion_avoidance_count
    # received an ACK pkt
    ack_num = Ack
    cwnd_list.append(window_size)
    if ack_num in ACK_dict[from_addr]:
        ACK_dict[from_addr][ack_num] += 1
        if ACK_dict[from_addr][ack_num] >= 4:       #是否要对其进行更改？
            ACK_dict[from_addr][ack_num] = -100
            if control_state[from_addr] != 2:
                ssthresh[from_addr] = max(window_size[from_addr] / 2, 2)
                window_size[from_addr] = ssthresh[from_addr] + 3
                congestion_avoidance_count[from_addr] = 0
                control_state[from_addr] = 0
            if control_state[from_addr] == 2:
                window_size[from_addr] += 1
            left = (ack_num) * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash[from_addr]][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1),  0)
            # -----------记录发送时间-------------------------------------
            time_recoder[from_addr][ack_num+1] = (time.time(), from_addr)
            # finished_send_dict[from_addr] = ack_num+1
            sock.sendto(data_header + next_data, from_addr)
    else:
        ACK_dict[from_addr][ack_num] = 1
        for packetid in list(time_recoder[from_addr].keys()):
            if packetid <= ack_num:
                time_recoder[from_addr].pop(packetid)

        if not control_state[from_addr]:
            window_size[from_addr] += 1
            congestion_avoidance_count[from_addr] = 0
        elif control_state[from_addr] == 2:
            window_size[from_addr] = ssthresh[from_addr]
            congestion_avoidance_count[from_addr] = 0
        elif control_state[from_addr]:
            congestion_avoidance_count[from_addr] += 1
            if congestion_avoidance_count[from_addr] == window_size[from_addr]:
                congestion_avoidance_count[from_addr] = 0
                window_size[from_addr] += 1
        if window_size[from_addr] >= ssthresh[from_addr]:
            control_state[from_addr] = 1
        if ack_num == 377 and from_addr[0] == 48008:
            print()
        while finished_send_dict[from_addr] < ack_num + window_size[from_addr] :
            if Ack == math.ceil(CHUNK_DATA_SIZE / MAX_PAYLOAD):
                # --------------断开连接-----------------------------------
                time_recoder.pop(from_addr)
                ex_sending_chunkhash.pop(from_addr)
                print(f"finished sending {ex_sending_chunkhash}")
                break
            elif finished_send_dict[from_addr] < math.ceil(CHUNK_DATA_SIZE / MAX_PAYLOAD):
                left = (finished_send_dict[from_addr]) * MAX_PAYLOAD
                right = min((finished_send_dict[from_addr] + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = config.haschunks[ex_sending_chunkhash[from_addr]][left: right]
                # send next data
                data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                          socket.htons(HEADER_LEN + len(next_data)), socket.htonl(finished_send_dict[from_addr] + 1), 0)
                finished_send_dict[from_addr] += 1
                # -----------记录发送时间-------------------------------------
                time_recoder[from_addr][finished_send_dict[from_addr]] = (time.time(), from_addr)
                sock.sendto(data_header + next_data, from_addr)
                continue
            break




def process_inbound_udp(sock):
    global config
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    Magic, hlen, plen, Seq, Ack = socket.ntohs(Magic), socket.ntohs(hlen), socket.ntohs(plen), socket.ntohl(Seq), socket.ntohl(Ack)
    data = pkt[HEADER_LEN:]
    print("SKELETON CODE CALLED, FILL this!")
    if Type == 0:
        deal_whohas(data, sock, from_addr)
    elif Type == 1:
        deal_ihave(data, sock, from_addr)
    elif Type == 2:
        deal_get(data, sock, from_addr)
    elif Type == 3:
        if from_addr in receive_connection:
            deal_data(data, Seq, sock, from_addr)
    elif Type == 4:
        if Ack in time_recoder[from_addr]:
            sample_RTT = time.time() - time_recoder[from_addr][Ack][0]
            update_RTT_TIMEOUT(sample_RTT)
            time_recoder[from_addr].pop(Ack)
        deal_ack(Ack, sock, from_addr)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def process_timeout(sock):
    global window_size, ssthresh, control_state, congestion_avoidance_count, ACK_dict
    current_time = time.time()
    for target_host, timeInfo in time_recoder.items():
        for packetid, info in timeInfo.items():
            if current_time - info[0] > 1.5*getTimeout():
                if packetid-1 in ACK_dict[info[1]]:
                    ACK_dict[info[1]][packetid - 1] = 1
                ssthresh[target_host] = max(window_size[target_host]/2, 2)
                window_size[target_host] = 1
                congestion_avoidance_count[target_host] = 0
                control_state[target_host] = 0
                left = (packetid-1) * MAX_PAYLOAD
                right = min((packetid) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = config.haschunks[ex_sending_chunkhash[target_host]][left: right]
                # send next data
                data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 3, socket.htons(HEADER_LEN),
                                          socket.htons(HEADER_LEN + len(next_data)), socket.htonl(packetid),  0)
                # -----------记录发送时间-------------------------------------
                time_recoder[target_host][packetid] = (time.time(), info[1])
                sock.sendto(data_header + next_data, info[1])
                break


def check_ihave(sock):
    global ihave_recoder
    for addr in ihave_recoder.keys():
        if time.time() - ihave_recoder[addr] > IHAVE_TIME:
            get_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 2, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN + len(receive_connection[addr])), socket.htonl(0), socket.htonl(0))
            get_pkt = get_header + receive_connection[addr]
            sock.sendto(get_pkt, addr)
            ihave_recoder[addr] = time.time()

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

def judgedie(sock):
    current_time = time.time()
    tmplist = list()
    for from_address, t in die_recoder.items():
        if current_time-t > CLOSED_TIME:
            chunkhash = receive_connection[from_address]
            receive_connection.pop(from_address)
            ex_received_chunk[bytes.hex(chunkhash)] = bytes()
            tmplist.append(from_address)
            file_cache.pop(from_address)
            finished_dict.pop(from_address)

            whohas_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, 0, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN + len(chunkhash)), socket.htonl(0), socket.htonl(0))
            whohas_pkt = whohas_header + chunkhash

            # Step3: flooding whohas to all peers in peer list
            peer_list = config.peers
            for p in peer_list:
                if int(p[0]) != config.identity:
                    sock.sendto(whohas_pkt, (p[1], int(p[2])))

    for address in tmplist:
        die_recoder.pop(address)

def peer_run(config):
    global time_recoder, count, die_recoder
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            check_ihave(sock)
            process_timeout(sock)
            judgedie(sock)
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
            # if count != len(finished_chunks) and len(receive_connection) == 0:
            #     complement_integrity(sock)
    except KeyboardInterrupt:
        pass
    finally:
        x = range(30)
        y = cwnd_list
        plt.plot(x, y, marker='D', markersize=5, label='cwnd')
        plt.xlabel("time/s")
        plt.ylabel("window_size/MSS")
        plt.savefig("cwnd.jpg")
        tem = traceback.format_exc()
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
