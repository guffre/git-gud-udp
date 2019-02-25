import random
import select
import socket
import struct
import time
import hashlib

# PACKET:
#
#     16          4          X
# [CHECKSUM][PACKET_NUMBER][DATA]

class GGUdp(object):
    def __init__(self, ip, port):
        self.define_globals()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = ip
        self.port = port
        self.addr = ((ip,port))
        self.server = False
    
    def bind(self):
        self.server = True
        self.s.bind((self.ip,self.port))
    
    def connect(self, ip, port):
        self.addr = ((ip,port))

    def byte_flatten(self, data):
        ret = bytearray()
        for n in data:
            ret += bytearray(n)
        return ret

    def struct_pack(self, data, format="I"):
        return bytearray(struct.pack(format, data))
    
    def struct_unpack(self, data, format="I"):
            return struct.unpack(format, data)[0]
    
    def add_header(self, data, packet_index):
        packet_number = self.struct_pack(packet_index)
        checksum      = self._checksum(packet_number + data)
        data_chunk    = "{}{}{}".format(checksum, packet_number, data)
        return data_chunk
    
    def chk_header(self, data):
        try:
            packet_index_bytes = data[self.LEN_CHECKSUM:self.LEN_CHECKSUM+self.LEN_PACKET_NUM]
            checksum     = bytearray(data[:self.LEN_CHECKSUM])
            packet_index = self.struct_unpack(packet_index_bytes)
            data_chunk   = data[self.LEN_HEADERS:]
            if self._checksum(packet_index_bytes + data_chunk) == checksum:
               return (packet_index, data_chunk)
        except:
            pass
        return (-1, bytearray("0"))
    
    def send(self, data):
        if len(data) <= 1:
            data += "pad"
        data = bytearray(data)
        # SYNC LOOP
        for _ in range(3):
            self._send(bytearray(str(len(data))))
            response,_ = self._recv(self.SYNC_TIMEOUT)
            if response == bytearray(str(len(data))):
                break
        else:
            print("Failed to sync with server")
            return False
        
        # SEND_DATA: [CHECKSUM]([PACKET_NUMBER][DATA])
        data_index   = 0
        packet_index = 0
        data_chunks = dict()
        while data_index < len(data):
            # Assemble packet data
            pktsize    = random.randint(self.MIN_DATA_SIZE, self.MAX_DATA_SIZE)
            data_chunk = self.add_header(data[data_index:data_index+pktsize], packet_index)
            # Add to chunk list
            data_chunks[packet_index] = data_chunk
            # Send data
            self._send(data_chunk)
            # Increment counters
            data_index   += pktsize
            packet_index += 1
            # This sleep helps avoid packet loss. Maybe add option to tune it.
            # No sleep is possibly fastest transfer at the cost of bandwidth (lots of dropped packets)
            if packet_index%10 == 0:
                time.sleep(0.005)
        self._send(self.DONE_SENDING)
        
        # HANDLE REREQUESTS
        retries = 3
        while True:
            while retries:
                data,_ = self._recv(self.SEND_REREQUEST_TIMEOUT)
                if data == "TIMEOUT":
                    retries -= 1
                else: break
            if data.startswith(self.MISSING_PACKETS):
                data = data[self.LEN_MISSING_PKT:]
                if len(data) == 0:
                    break
                count = 0
                time.sleep(0.1)
                for i in range(0, len(data), self.LEN_MISSING_PKT):
                    count += 1
                    missing_index_bytes = data[i:i+self.LEN_MISSING_PKT]
                    missing_index = self.struct_unpack(missing_index_bytes)
                    to_send = data_chunks.get(missing_index, self.OUT_OF_RANGE+missing_index_bytes)
                    self._send(to_send)
                    if count%30 == 0:
                         time.sleep(0.001)
                    if to_send.startswith(self.OUT_OF_RANGE):
                        break
            else:
                print("Bad packet order? No missing packets packet missed.")
                break

        tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)
        while tmp != "TIMEOUT":
            tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)
        return True

    def recv(self, timeout=False):
        # SYNC LOOP
        len_data,addr = self._recv(timeout)
        if self.server:
            self.addr = addr
        try:
            len_data = int(len_data)
            self._send(bytearray(str(len_data)))
        except:
            self.s.close()
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.server:
                self.s.bind((self.ip,self.port))
            return False
        
        # RECEIVE DATA
        data = dict({-1:-1})
        received = 0
        while received < len_data:
            data_chunk,_   = self._recv(self.RECV_LOOP_TIMEOUT)
            if data_chunk == "TIMEOUT" or data_chunk == self.DONE_SENDING:
                break
            packet_index,data_chunk = self.chk_header(data_chunk)
            if packet_index >= 0:
                data[packet_index] = data_chunk
                received += len(data_chunk)

        # Clear receive buffer of DONE_SENDING and get missing_packet sync
        try:
            while data_chunk == self.DONE_SENDING:
                data_chunk,_ = self._recv(self.TIMEOUT_NO_WAIT)
        except:
            pass
        # SEND REREQUESTS
        d_max = 0
        retries = self.REREQUEST_SAFETY
        while (received != len_data):
            missing_packet_max = 1+((len_data - received)/self.MIN_DATA_SIZE)
            missing = [self.MISSING_PACKETS]
            # Get list of missing chunks
            if not d_max:
                d_max = max(data)+missing_packet_max
            for i in range(d_max):
                if i not in data:
                    missing.append(self.struct_pack(i))
                if (len(missing)*self.LEN_MISSING_PKT) >= (self.MAX_DATA_SIZE - self.LEN_MISSING_PKT):
                    break
            # Send missing chunk request
            self._send(self.byte_flatten(missing))
            # If length is 1, no more missing packets!
            if (len(missing) == 1) or (received == len_data):
                break
            # Attempt to receive each missing packet
            for i in missing[1:]:
                data_chunk,_ = self._recv(self.RECV_REREQUEST_TIMEOUT)
                if data_chunk.startswith(self.OUT_OF_RANGE):
                    d_max = min(d_max, self.struct_unpack(data_chunk[len(self.OUT_OF_RANGE):]))
                    break
                if data_chunk == "TIMEOUT":
                    retries -= 1
                    break
                else:
                    retries = self.REREQUEST_SAFETY
                    packet_index,data_chunk = self.chk_header(data_chunk)
                    if packet_index >= 0:
                        if data.get(packet_index, False):
                            received -= len(data[packet_index])
                        received += len(data_chunk)
                        data[packet_index] = data_chunk
                if received == len_data:
                    break
            if retries == 0:
                print("Didn't receive all data")
                break
        else: # No missing packets
            self._send(str(self.MISSING_PACKETS))

        tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)
        while tmp != "TIMEOUT":
            tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)

        self.s.close()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.server:
            self.s.bind((self.ip,self.port))
        
        if retries == 0:
            return False
        
        _ = data.pop(-1)
        return self.byte_flatten(data[n] for n in sorted(data))
    
    def _checksum(self, data):
        return bytearray(hashlib.md5(data).digest())
    
    def _send(self, data):
        self.s.setblocking(1)
        self.s.sendto(data, self.addr)
    
    def _recv(self, timeout=False):
        data,addr = "TIMEOUT",False
        if timeout == False:
            self.s.setblocking(1)
            data,addr = self.s.recvfrom(self.MAX_PACKET_SIZE)
        else:
            self.s.setblocking(0)
            try:
                ready = select.select([self.s], [], [], timeout)
                if ready[0]:
                    data,addr = self.s.recvfrom(self.MAX_PACKET_SIZE)
            except:
                pass
        return data,addr
    
    def define_globals(self):
        # Special packets
        self.MISSING_PACKETS = self.struct_pack(0x155168C7)
        self.OUT_OF_RANGE    = self.struct_pack(0x070F124E)
        self.DONE_SENDING    = self.struct_pack(0xD0E53D16)
        self.LEN_MISSING_PKT = len(self.MISSING_PACKETS)

        # Headers
        self.LEN_PACKET_NUM = len(self.struct_pack(0))
        self.LEN_CHECKSUM   = len(self._checksum("0"))
        self.LEN_HEADERS    = self.LEN_PACKET_NUM + self.LEN_CHECKSUM

        # Packet length info
        self.MAX_PACKET_SIZE = 4096
        self.MIN_DATA_SIZE   = 500
        self.MAX_DATA_SIZE   = self.MAX_PACKET_SIZE - self.LEN_HEADERS

        # Timeout values
        self.REREQUEST_SAFETY  = 10
        self.SYNC_TIMEOUT      = 1
        self.RECV_LOOP_TIMEOUT = 5
        self.TIMEOUT_NO_WAIT   = 0.1
        self.SEND_REREQUEST_TIMEOUT = 8 # Must be higher than RECV_REREQUEST_TIMEOUT
        self.RECV_REREQUEST_TIMEOUT = 0.5

        # Note, REREQUEST_SAFETY * RECV_REREQUEST_TIMEOUT is roughly how much time it takes to TIMEOUT a rerequest loop
        # If absolutely no packets get received. Each time a successful rerequest comes through though, REREQUEST_SAFETY gets reset
        # I feel 5 seconds total is generous, but for less reliable networks you might tweak these values

        # Example setup:
        # For a network with roughly 5 second latency between points, this might be more appropriate:
        # REREQUEST_SAFETY = 10
        # SYNC_TIMEOUT = 6
        # RECV_LOOP_TIMEOUT = 8
        # TIMEOUT_NO_WAIT = 0.05
        # SEND_REREQUEST_TIMEOUT = 15
        # RECV_REREQUEST_TIMEOUT = 3.5