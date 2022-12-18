# import time
# import struct
#
# BUF_SIZE = 1400
# HEADER_LEN = struct.calcsize("HBBHHII")
# CHUNK_DATA_SIZE = 512 * 1024
# MAX_PAYLOAD = 1024
# MAGIC = 52305
# TEAM = 27
#
# # 超时重传机制相关参数
# TIMEOUT = 1  # 超时时间，单位为秒
# MAX_RETRIES = 3  # 最大重传次数
#
# # 拥塞控制机制相关参数
# MIN_INTERVAL = 0.1  # 最小 ACK 包时间间隔，单位为秒
# MAX_INTERVAL = 1  # 最大 ACK 包时间间隔，单位为秒
#
# config = None
# ex_output_file = None
# ex_received_chunk = dict()
# ex_downloading_chunkhash = ""
#
# # 发送队列，用于存储待发送的数据包
# send_queue = []
#
# # 超时重传机制相关变量
# last_ack_time = 0  # 上一次收到 ACK 包的时间
# send_interval = MIN_INTERVAL  # 发送速率，单位为秒
#
# # 序列号计数器
# seq_num = 0
#
#
# def process_download(sock, chunkfile, outputfile):
#     global ex_output_file
#     global ex_received_chunk
#     global ex_downloading_chunkhash
#     global send_queue
#
#     ex_output_file = outputfile
#     # Step 1: read chunkhash to
#     download_hash = bytes()
#     with open(chunkfile, 'r') as cf:
#         index, datahash_str = cf.readline().strip().split(" ")
#         ex_received_chunk[datahash_str] = bytes()
#         ex_downloading_chunkhash = datahash_str
#         # hex_str to bytes
#     datahash = bytes.fromhex(datahash_str)
#     download_hash = download_hash + datahash
#
#     # Step2: make WHOHAS pkt
#     # |2byte magic|1byte type |1byte team|
#     # |2byte  header len  |2byte pkt len |
#     # |      4byte  seq                  |
#     # |      4byte  ack                  |
#     whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0, socket.htons(HEADER_LEN),
#                                 socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
#     whohas_pkt = whohas_header + download_hash
#
#     # Step3: flooding whohas to all peers in peer list
#     peer_list = config.peers
#     for p in peer_list:
#         if int(p[0]) != config.identity:
#             send_queue.append((whohas_pkt, (p[1], int(p[2]))))
#
#     # 开启超时重传机制
#     last_ack_time = time.time()
#     while True:
#         # 处理超时重传机制
#         current_time = time.time()
#         if current_time - last_ack_time > TIMEOUT:
#             # 如果超时，则重新发送所有待发送的数据包
#             for pkt, addr in send_queue:
#                 sock.sendto(pkt, addr)
#             last_ack_time = current_time
#
#         # 处理接收到的数据包
#         pkt, from_addr = sock.recvfrom(BUF_SIZE)
#         Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
#         data = pkt[HEADER_LEN:]
#         if Type == 0:
#             # received an WHOHAS pkt
#             # see what chunk the sender has
#             whohas_chunk_hash = data[:20]
#             # bytes to hex_str
#             chunkhash_str = bytes.hex(whohas_chunk_hash)
#             ex_sending_chunkhash = chunkhash_str
#
#             print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
#             if chunkhash_str in config.haschunks:
#                 ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1, socket.htons(HEADER_LEN),
#                                            socket.htons(HEADER_LEN + len(whohas_chunk_hash)), socket.htonl(0),
#                                            socket.htonl(0))
#             ihave_pkt = ihave_header + whohas_chunk_hash
#             send_queue.append((ihave_pkt, from_addr))
#         elif Type == 1:
#             # received an IHAVE pkt
#             # see what chunk the sender has
#             ihave_chunk_hash = data[:20]
#             # bytes to hex_str
#             chunkhash_str = bytes.hex(ihave_chunk_hash)
#             if chunkhash_str == ex_downloading_chunkhash:
#                 # send back GET pkt
#                 get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
#                                          socket.htons(HEADER_LEN + len(ihave_chunk_hash)), socket.htonl(0),
#                                          socket.htonl(0))
#                 get_pkt = get_header + ihave_chunk_hash
#                 send_queue.append((get_pkt, from_addr))
#         elif Type == 2:
#             # received a GET pkt
#             # see what chunk the sender wants
#             get_chunk_hash = data[:20]
#             # bytes to hex_str
#             chunkhash_str = bytes.hex(get_chunk_hash)
#             if chunkhash_str in config.haschunks:
#                 # send back DATA pkt
#                 chunk_data = config.haschunks[chunkhash_str]
#                 data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
#                                           socket.htons(HEADER_LEN + len(chunk_data)), socket.htonl(0),
#                                           socket.htonl(0))
#                 data_pkt = data_header + chunk_data
#                 send_queue.append((data_pkt, from_addr))
#         elif Type == 3:
#             # received a DATA pkt
#             # see what chunk the sender is sending
#             data_chunk_hash = data[:20]
#             # bytes to hex_str
#             chunkhash_str = bytes.hex(data_chunk_hash)
#             if chunkhash_str == ex_downloading_chunkhash:
#                 # store the chunk
#                 chunk_data = data[20:]
#                 ex_received_chunk[chunkhash_str] += chunk_data
#                 if len(ex_received_chunk[chunkhash_str]) == CHUNK_DATA_SIZE:
#             # received a complete chunk, write to file
#             with open(ex_output_file, 'wb') as f:
#                 f.write(ex_received_chunk[chunkhash_str])
#             ack_header = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN),
#                                      socket.htons(HEADER_LEN + len(data_chunk_hash)), socket.htonl(0),
#                                      socket.htonl(0))
#             ack_pkt = ack_header + data_chunk_hash
#             send_queue.append((ack_pkt, from_addr))
#         elif Type == 4:
#             # received an ACK pkt
#             # see what chunk the sender has received
#             ack_chunk_hash = data[:20]
#             # bytes to hex_str
#             chunkhash_str = bytes.hex(ack_chunk_hash)
#             if chunkhash_str == ex_downloading_chunkhash:
#                 # download complete, exit loop
#                 break
#
#             # 拥塞控制机制
#         if send_interval < MAX_INTERVAL:
#             send_interval += (current_time - last_ack_time) / (2 * send_interval)
#         last_ack_time = current_time
#         time.sleep(send_interval)
#
