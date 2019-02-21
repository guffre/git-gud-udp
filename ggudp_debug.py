import random
import select
import socket
import struct
import sys
import time
import tempfile
import hashlib

# structs can have different lengths, but Ive found "I" to reliably be 4 bytes.
# if struct.pack("I", 0) is not length `4`, stuff is going to break.
# You can replace the struct types here: and in the class struct_pack and struct_unpack
MISSING_PACKETS  = struct.pack("I", 0x155168C7)
OUT_OF_RANGE     = struct.pack("I", 0x070F124E)
DONE_SENDING     = struct.pack("I", 0xD0E53D16)
LEN_PACKET_NUM   = len(struct.pack("I", 0))
LEN_MISSING_PKT  = len(MISSING_PACKETS)
LEN_CHECKSUM     = len(bytearray(hashlib.md5("0").digest()))
CONNECT_TIMEOUT  = 20
RECV_LOOP_TIMEOUT = 10 # This should be something low
TIMEOUT_NO_WAIT = 0.05
MAX_PACKET_SIZE = 4096
MIN_DATA_SIZE   = 500
MAX_DATA_SIZE   = MAX_PACKET_SIZE - LEN_CHECKSUM - LEN_PACKET_NUM
MAX_RETRY_TIMEOUT = 10

# PACKET:
#
#     16          4          X
# [CHECKSUM][PACKET_NUMBER][DATA]

class GGUdp(object):
    def __init__(self, ip, port, server=False):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = ip
        self.port = port
        self.addr = ((ip,port))
        self.server = server
        # If port is specified, this means its a server
        if server:
            self.s.bind((ip, port))
    
    def struct_pack(self, data, length=4):
        if length == 4:
            return struct.pack("I", data)
    
    def struct_unpack(self, data, length=4):
        if length == 4:
            return struct.unpack("I", data)
    
    def _pack_packet(self, data, packet_index):
        packet_number = self.struct_pack(packet_index)
        data_chunk    = "{}{}".format(packet_number, data)
        checksum      = self._checksum(data_chunk)
        data_chunk    = "{}{}".format(checksum, data_chunk)
        return data_chunk
    
    def _unpack_packet(self, data):
        checksum     = bytearray(data[:LEN_CHECKSUM])
        try:
            packet_index = self.struct_unpack(data[LEN_CHECKSUM:LEN_CHECKSUM+LEN_PACKET_NUM])[0]
        except:
            print("ERROR]{}".format(repr(data)))
            return (-1, bytearray("0"))
        data_chunk   = data[LEN_CHECKSUM+LEN_PACKET_NUM:]
        if self._checksum(data[LEN_CHECKSUM:]) == checksum:
            print("Returning packet info")
            return (packet_index, data_chunk)
        print("returning FALSE")
        print("checksum]{}".format(repr(checksum)))
        print("packet_index]{}".format(repr(packet_index)))
        print("data_chunk]{}".format(repr(data_chunk)))
        print("calcchksum]{}".format(repr(self._checksum(data[LEN_CHECKSUM:]))))
        return (-1, bytearray("0"))
    
    def send(self, data):
        data = bytearray(data)
        # SYNC LOOP
        timeout = 5
        while timeout <= 15:
            #print("send]{}".format(repr(data)))
            self._send(bytearray(str(len(data))))
            response = self._recv(timeout)
            print("resp]{}".format(repr(response)))
            if response == bytearray(str(len(data))):
                break
            timeout += 5
        else:
            print("Failed to sync with server")
            return False
        
        # SEND_DATA: [CHECKSUM]([PACKET_NUMBER][DATA])
        data_index   = 0
        packet_index = 0
        data_chunks = dict()
        while data_index < len(data):
            # Assemble packet data
            pktsize    = random.randint(MIN_DATA_SIZE, MAX_DATA_SIZE)
            data_chunk = self._pack_packet(data[data_index:data_index+pktsize], packet_index)
            # Add to chunk list
            data_chunks[packet_index] = data_chunk
            # Send data
            print("send][{}][{}]".format(self.addr,packet_index))
            #0.001 = ~1.5MB/s, python wont sleep any shorter than this
            # Testing with a 1gig up connection across the world, packet loss is too high to be efficient
            # So, I lower the speed here. This ends up ~9MB/s and minimal packet loss.
            if packet_index%5 == 0:
                time.sleep(0.001)
            # Increment counters
            data_index   += pktsize
            packet_index += 1
        self._send(bytearray(DONE_SENDING))
        self._send(bytearray(DONE_SENDING))
        
        # HANDLE REREQUESTS
        retries = 3
        while True:
            print("rerequest loop]")
            while retries:
                print("retries]{}".format(retries))
                data = self._recv(CONNECT_TIMEOUT)
                if data == "TIMEOUT":
                    retries -= 1
                else: break
            print("got data]{}".format(repr(data)))
            if data.startswith(MISSING_PACKETS):
                print("[rerequest]")
                data = data[LEN_MISSING_PKT:]
                if len(data) == 0:
                    print("No missing packets")
                    break
                for i in range(0, len(data), LEN_MISSING_PKT):
                    missing_index_bytes = data[i:i+LEN_MISSING_PKT]
                    missing_index = self.struct_unpack(missing_index_bytes)[0]
                    print(missing_index)
                    to_send = data_chunks.get(missing_index, OUT_OF_RANGE+missing_index_bytes)
                    self._send(to_send)
                    if to_send.startswith(OUT_OF_RANGE):
                        break
            else:
                print("Bad packet order? No missing packets packet missed.")
                break

        tmp = self._recv(TIMEOUT_NO_WAIT)
        while tmp != "TIMEOUT":
            tmp = self._recv(TIMEOUT_NO_WAIT)
            print("flushing: {}".format(repr(tmp)))
        return True
    
    def recv(self, timeout=CONNECT_TIMEOUT):
        # SYNC LOOP
        if self.server: # Server should not timeout when receiving
            print("server recv")
            self.s.setblocking(1)
            len_data,self.addr = self.s.recvfrom(MAX_PACKET_SIZE)
            #print("recv->send]{}".format(repr(len_data)))
        else:
            len_data = self._recv(timeout)
        try:
            len_data = int(len_data)
            self._send(bytearray(str(len_data)))
        except:
            #print("Not valid gudp")
            return False
        
        # RECEIVE DATA
        data = dict()
        received = 0
        while received < len_data:
            data_chunk   = self._recv(RECV_LOOP_TIMEOUT)
            if data_chunk == "TIMEOUT" or data_chunk == DONE_SENDING:
                break
            #print("recv]{}".format(repr(data_chunk)))
            packet_index,data_chunk = self._unpack_packet(data_chunk)
            print("d[{}] = data".format(repr(packet_index)))
            if packet_index >= 0:
                print("ADDED")
                data[packet_index] = data_chunk
                received += len(data_chunk)
            print("received]{}".format(received))
            print("len_data]{}".format(len_data))

        # Clear receive buffer of DONE_SENDING and get missing_packet sync
        try:
            while data_chunk == DONE_SENDING:
                data_chunk = self._recv(1)
        except:
            print("no data chunk")
            pass
        #print("\ndata]{}\n".format(repr(data)))
        # SEND REREQUESTS
        print("retrying")
        d_max = 0
        retries = MAX_RETRY_TIMEOUT
        while (received != len_data) and retries >= 0:
            missing_packet_max = 1+((len_data - received)/MIN_DATA_SIZE)
            print("missing_packet_max]{}".format(repr(missing_packet_max)))
            missing = [MISSING_PACKETS]
            # Get list of missing chunks
            if not d_max:
                try:
                    d_max = max(data)+missing_packet_max
                except:
                    d_max = missing_packet_max
                print("dmax]{}".format(repr(d_max)))
            for i in range(d_max):
                if i not in data:
                    missing.append(self.struct_pack(i))
                if (len(missing)*LEN_MISSING_PKT) >= (MAX_DATA_SIZE - LEN_MISSING_PKT): # Be safe, just to avoid off by one
                    print("Struct too big, break it off")
                    break
            #print("Missing]{}".format(missing))
            self._send(''.join(missing))
            # If length is 1, no more missing packets!
            if (len(missing) == 1) or (received == len_data):
                print("done break?")
                break
            print("catching missing packets!")
            for i in missing[1:]:
                print("receiving missing]{}".format(repr(i)))
                data_chunk = self._recv(TIMEOUT_NO_WAIT)
                #print("i?]{}".format(repr(data_chunk)))
                if data_chunk.startswith(OUT_OF_RANGE):
                    d_max = min(d_max, self.struct_unpack(data_chunk[len(OUT_OF_RANGE):])[0])
                    print("OUT OF RANGE: {}".format(d_max))
                    break
                if data_chunk == "TIMEOUT":
                    retries -= 1
                    break
                else:
                    retries = MAX_RETRY_TIMEOUT
                    packet_index,data_chunk = self._unpack_packet(data_chunk)
                    print("got a packet:{}|{}b".format(packet_index, len(data_chunk)))
                    if packet_index >= 0:
                        if data.get(packet_index, False):
                            received -= len(data[packet_index])
                        received += len(data_chunk)
                        data[packet_index] = data_chunk
                if received == len_data:
                    break
            print("Received]{}".format(received))
            print("len_data]{}".format(len_data))
        else: # No missing packets
            self._send(str(MISSING_PACKETS))
            self._send(str(MISSING_PACKETS))
        print("DONE? Received]{}".format(received))
        print("DONE? len_data]{}".format(len_data))

        tmp = self._recv(TIMEOUT_NO_WAIT)
        while tmp != "TIMEOUT":
            tmp = self._recv(TIMEOUT_NO_WAIT)
            print("flushing: {}".format(repr(tmp)))

        return bytearray(''.join(data[n] for n in sorted(data)))
    
    def _checksum(self, data):
        return bytearray(hashlib.md5(data).digest())
    
    def _send(self, data):
        #print("s|{}]{}".format(self.addr, data))
        print("sending data")
        self.s.sendto(data, self.addr)
    
    def _recv(self, timeout):
        self.s.setblocking(0)
        print("select]")
        ready = select.select([self.s], [], [], timeout)
        if ready[0]:
            while True:
                try:
                    data,_ = self.s.recvfrom(MAX_PACKET_SIZE)
                    break
                except:
                    print("error")
                    time.sleep(0.1)
            self.s.setblocking(1)
        else:
            print("TIMEOUT")
            data = "TIMEOUT"
        return data

if __name__ == '__main__':
    if sys.argv[1] == "s":
        s = GGUdp("0.0.0.0", 8000, True)
        while True:
            data = s.recv()
            if data:
                print("Got [{}] bytes".format(len(data)))
                tmpfile = tempfile.mktemp()
                with open(tmpfile, "wb") as f:
                    f.write(data)
                    print("File downloaded to: {}".format(tmpfile))
    else:
        s = GGUdp("127.0.0.1", 8000)
        with open(r"X:\cab1.cab", "rb") as f:
            data = f.read()
        s.send(data)
