import binascii
import hashlib
import random
import select
import socket
import struct
import time


class RC4(object):
    def __init__(self, key):
        self.stream = True
        key = bytearray(key)
        self.keystream = self.PRGA(self.KSA(key))
    
    def KSA(self, key):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S
    
    def PRGA(self, S):
        i, j = (0, 0)
        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            yield K
    
    def crypt(self, byte):
        return byte ^ self.keystream.next()
    
    @classmethod
    def make_key(self, key):
        random.seed(key)
        return bytearray([random.randint(0,255) for _ in xrange(32)])


class DH(object):
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        self.g = 2
        self.secret = random.randint(1, self.p-1)
        # Want public as a byte-stream
        public = "%x" % pow(self.g, self.secret, self.p)
        if len(public) % 2:
            public = '0' + public
        self.public = binascii.unhexlify(public)
    
    def get(self, shared):
        self.key = pow(shared, self.secret, self.p)
        return self.key


class GGUdp(object):
    """ A protocol wrapper that makes UDP transfers reliable and encrypted.
        PACKET:
            16        4        X
        [CHECKSUM][PACKET_ID][DATA]
    """
    def __init__(self, ip, port):
        # Special packets
        self.PKT_MISSING = self.__struct_pack(0x155168C7)
        self.PKT_OUT_OF_RANGE = self.__struct_pack(0x070F124E)
        self.PKT_DONE_SENDING = self.__struct_pack(0xD0E53D16)
        
        # Headers
        self.LEN_PKT_MISSING  = len(self.PKT_MISSING)
        self.LEN_PACKET_ID = len(self.__struct_pack(0))
        self.LEN_CHECKSUM  = len(self.__checksum("0"))
        self.LEN_HEADERS   = self.LEN_PACKET_ID + self.LEN_CHECKSUM

        # Packet length info
        self.MAX_PACKET_SIZE = 4096
        self.MIN_DATA_SIZE   = 500
        self.MAX_DATA_SIZE   = self.MAX_PACKET_SIZE - self.LEN_HEADERS

        # Timeout values
        self.TIMEOUT_REREQUEST_SAFETY  = 10
        self.TIMEOUT_SYNC      = 1
        self.TIMEOUT_RECV_LOOP = 5
        self.TIMEOUT_NO_WAIT   = 0.1
        self.TIMEOUT_SEND_REREQUEST = 8 # Must be higher than RECV_REREQUEST
        self.TIMEOUT_RECV_REREQUEST = 0.5
        
        # Socket information
        self._s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._ip = ip
        self._port = port
        self._addr = ((ip,port))
        self._server = False
        
        # Encryption
        self.encryption = RC4
        self._crypt = False
    
    def bind(self):
        self._server = True
        self._s.bind((self._ip, self._port))
    
    def connect(self, ip, port):
        self._addr = ((ip, port))

    def _byte_flatten(self, data):
        ret = bytearray()
        for n in data:
            ret += bytearray(n)
        return ret

    def __struct_pack(self, data, format="I"):
        return bytearray(struct.pack(format, data))
    
    def __struct_unpack(self, data, format="I"):
            return struct.unpack(format, data)[0]
    
    def __add_header(self, data, packet_index):
        packet_id  = self.__struct_pack(packet_index)
        checksum   = self.__checksum(packet_id + data)
        data_chunk = "{}{}{}".format(checksum, packet_id, data)
        return data_chunk
    
    def __chk_header(self, data):
        try:
            checksum = bytearray(data[:self.LEN_CHECKSUM])
            packet_index_bytes = data[self.LEN_CHECKSUM:self.LEN_CHECKSUM + self.LEN_PACKET_ID]
            packet_index = self.__struct_unpack(packet_index_bytes)
            data_chunk   = data[self.LEN_HEADERS:]
            if self.__checksum(packet_index_bytes + data_chunk) == checksum:
               return (packet_index, data_chunk)
        except:
            pass
        return (-1, bytearray("0"))
    
    def __encrypt(self, data):
        data = bytearray(data)
        if self._crypt.stream:
            for i,byte in enumerate(data):
                data[i] = self._crypt.crypt(byte)
        else:
            data = self._crypt.crypt(data)
        return data
    
    def __check_dh_exchange(self, data, keygen, pkt_type):
        keylen = self.__struct_unpack(data[:4])
        sharedkey = data[4:keylen+4]
        key = keygen.get(int(binascii.hexlify(sharedkey), 16))
        key = self.encryption.make_key(key)
        self._crypt = self.encryption(key)
        if pkt_type == "SYN":
            len_data = data[-4:]
            return len_data
        else: # ACK
            data = data[-4:]
            data = self.__encrypt(data)
            response = self.__struct_unpack(data)
            return response
    
    def send(self, data, encrypted=False):
        if len(data) <= 1:
            data += "pad"
        data = bytearray(data)
        # SYNC LOOP
        for _ in range(3):
            if encrypted:
                # SYN: [KEY LENGTH][KEY][DATA LENGTH]
                # ACK: [KEY LENGTH][KEY][ENCRYPTED DATA LENGTH]
                keygen = DH()
                blob = self.__struct_pack(len(keygen.public))
                blob += keygen.public
                blob += self.__struct_pack(len(data))
                self._send(blob)
                response,_ = self._recv(self.TIMEOUT_SYNC)
                if self.__check_dh_exchange(response, keygen, "ACK") == len(data):
                    break
            else:
                self._send(bytearray(str(len(data))))
                response,_ = self._recv(self.TIMEOUT_SYNC)
                if response == bytearray(str(len(data))):
                    break
        else:
            print("Failed to sync with server")
            return False
        
        # SEND_DATA: [CHECKSUM]([PACKET_ID][DATA])
        data_index   = 0
        packet_index = 0
        data_chunks = dict()
        while data_index < len(data):
            # Assemble packet data
            pktsize = random.randint(self.MIN_DATA_SIZE, self.MAX_DATA_SIZE)
            # ENCRYPT DATA BEFORE SENDING
            datachunk = data[data_index:data_index + pktsize]
            if encrypted:
                datachunk = self.__encrypt(datachunk)
            packet = self.__add_header(datachunk, packet_index)
            # Add to chunk list
            data_chunks[packet_index] = packet
            # Send data
            self._send(packet)
            # Increment counters
            data_index   += pktsize
            packet_index += 1
            # This sleep helps avoid packet loss. Maybe add option to tune it.
            # No sleep is possibly fastest transfer at the cost of bandwidth (lots of dropped packets)
            if packet_index % 10 == 0:
                time.sleep(0.005)
        self._send(self.PKT_DONE_SENDING)
        
        # HANDLE REREQUESTS
        retries = 3
        while True:
            while retries:
                data,_ = self._recv(self.TIMEOUT_SEND_REREQUEST)
                if data == "TIMEOUT":
                    retries -= 1
                else: break
            if data.startswith(self.PKT_MISSING):
                data = data[self.LEN_PKT_MISSING:]
                if len(data) == 0:
                    break
                count = 0
                time.sleep(0.1)
                for i in range(0, len(data), self.LEN_PKT_MISSING):
                    count += 1
                    missing_index_bytes = data[i:i + self.LEN_PKT_MISSING]
                    missing_index = self.__struct_unpack(missing_index_bytes)
                    to_send = data_chunks.get(missing_index, self.PKT_OUT_OF_RANGE + missing_index_bytes)
                    self._send(to_send)
                    if count%30 == 0:
                         time.sleep(0.001)
                    if to_send.startswith(self.PKT_OUT_OF_RANGE):
                        break
            else:
                print("Bad packet order? No missing packets packet missed.")
                break

        tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)
        while tmp != "TIMEOUT":
            tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)
        return True

    def recv(self, timeout=False, encrypted=False):
        # SYNC LOOP
        # SYN: [KEY LENGTH][KEY][DATA LENGTH]
        # ACK: [KEY LENGTH][KEY][ENCRYPTED DATA LENGTH]
        blob, addr = self._recv(timeout)
        if self._server:
            self._addr = addr
        #try:
        if encrypted:
            keygen = DH()
            len_data = self.__check_dh_exchange(blob, keygen, "SYN")
            blob = self.__struct_pack(len(keygen.public))
            blob += keygen.public
            blob += self.__encrypt(len_data)
            len_data = self.__struct_unpack(len_data)
            self._send(blob)
        else:
            len_data = int(blob)
            self._send(bytearray(str(len_data)))
        # except Exception as e:
        #     print(e)
        #     self._s.close()
        #     self._s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #     if self._server:
        #         self._s.bind((self._ip, self._port))
        #     return False
        
        # RECEIVE DATA
        data = dict({-1:-1})
        received = 0
        while received < len_data:
            data_chunk,_   = self._recv(self.TIMEOUT_RECV_LOOP)
            if data_chunk == "TIMEOUT" or data_chunk == self.PKT_DONE_SENDING:
                break
            packet_index,data_chunk = self.__chk_header(data_chunk)
            if packet_index >= 0:
                data[packet_index] = data_chunk
                received += len(data_chunk)

        # Clear receive buffer of DONE_SENDING and get missing_packet sync
        try:
            while data_chunk == self.PKT_DONE_SENDING:
                data_chunk,_ = self._recv(self.TIMEOUT_NO_WAIT)
        except:
            pass
        # SEND REREQUESTS
        d_max = 0
        retries = self.TIMEOUT_REREQUEST_SAFETY
        while (received != len_data):
            print(len_data, received)
            missing_packet_max = 1 + ((len_data - received) / self.MIN_DATA_SIZE)
            missing = [self.PKT_MISSING]
            # Get list of missing chunks
            if not d_max:
                d_max = max(data) + missing_packet_max
            for i in range(d_max):
                if i not in data:
                    missing.append(self.__struct_pack(i))
                if (len(missing) * self.LEN_PKT_MISSING) >= (self.MAX_DATA_SIZE - self.LEN_PKT_MISSING):
                    break
            # Send missing chunk request
            self._send(self._byte_flatten(missing))
            # If length is 1, no more missing packets!
            if (len(missing) == 1) or (received == len_data):
                break
            # Attempt to receive each missing packet
            for i in missing[1:]:
                data_chunk,_ = self._recv(self.TIMEOUT_RECV_REREQUEST)
                if data_chunk.startswith(self.PKT_OUT_OF_RANGE):
                    d_max = min(d_max, self.__struct_unpack(data_chunk[len(self.PKT_OUT_OF_RANGE):]))
                    break
                if data_chunk == "TIMEOUT":
                    retries -= 1
                    break
                else:
                    retries = self.TIMEOUT_REREQUEST_SAFETY
                    packet_index,data_chunk = self.__chk_header(data_chunk)
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
            self._send(str(self.PKT_MISSING))

        tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)
        while tmp != "TIMEOUT":
            tmp,_ = self._recv(self.TIMEOUT_NO_WAIT)

        self._s.close()
        self._s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self._server:
            self._s.bind((self._ip,self._port))
        
        if retries == 0:
            return False
        
        _ = data.pop(-1)
        if encrypted:
            if self._crypt.stream:
                data = self._byte_flatten(data[n] for n in sorted(data))
                data = self.__encrypt(data)
            else:
                for index in sorted(data):
                    data[index] = self.__encrypt(data[index])
                data = self._byte_flatten(data[n] for n in sorted(data))
        else:
            data = self._byte_flatten(data[n] for n in sorted(data))
        
        return data
    
    def secure_send(self, data):
        return self.send(data, True)
    
    def secure_recv(self, timeout=False):
        return self.recv(timeout, True)
    
    def __checksum(self, data):
        return bytearray(hashlib.md5(data).digest())
    
    def _send(self, data):
        self._s.setblocking(1)
        self._s.sendto(data, self._addr)
    
    def _recv(self, timeout=False):
        data, addr = "TIMEOUT", False
        if timeout == False:
            self._s.setblocking(1)
            data, addr = self._s.recvfrom(self.MAX_PACKET_SIZE)
        else:
            self._s.setblocking(0)
            try:
                ready = select.select([self._s], [], [], timeout)
                if ready[0]:
                    data, addr = self._s.recvfrom(self.MAX_PACKET_SIZE)
            except:
                pass
        return data, addr
