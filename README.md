# git-gud-udp
<<<<<<< HEAD
A reliable UDP transfer with fairly low overhead. No dependencies, written in Python 2.7
Includes optional "secure_send" and "secure_recv" for built-in data-in-transit encryption using Diffie-Hellmann + RC4.

The encryption is swappable between stream and block ciphers though. Simply change:
    GGUdp.encryption = RC4
    
to point to the encryption class of your choice. That class must have three things though to be compatible:
1) A variable indicating if it is a stream-cipher, ie `self.stream = True`
2) A `make_key` as a class-method, that creates the key that will be used. The argument is a Python long, and it can return anything that YourEncryption.__init__() will accept as a key.
3) A class method `crypt`. For stream-ciphers, it must accept individual bytes. For block-ciphers, it must accept arbitrarily-sized data that will be between 3 and `GGUdp.MAX_DATA_SIZE` bytes.
=======
An attempt at reliable UDP transfer with fairly low overhead. No dependencies, written in 2.7  
I was informed this appears to be an implementation of Selective Repeat Error Recovery, so it should be pretty dependable!
>>>>>>> 39b8acbbc10716f7c026d4b4b64b602b8a888127

# Packet Info
 [CHECKSUM]\([PACKET_NUMBER][DATA]\)
 
 Currently, checksum is implemented as an MD5 hash of PACKET_NUMBER+DATA
 Packets are randomly sized between MIN_DATA_SIZE and MAX_DATA_SIZE.
 This defaults to data sizes between 500 and 4082
 
 NOTE: The ggudp protocol automatically handle sizes for you, so theres no need to specify size when `send()`ing or `recv()ing`. That said, a single `send()/recv()` gets stored in memory (just like with TCP) so your program should chunk data if youre sending/recieving something exceptionally large.
 
 `send()` and `recv()` will return `False` if data fails to transfer reliably.

# Example Usage
 ## Client:
     s = GGUdp("127.0.0.1", 8000)
     data = "hello world"
     s.send(data)
 
 ## Server:
      s = GGUdp("0.0.0.0", 8000)
      s.bind()
      while True:
          data = s.recv()
          if data:
              print(data)


# Timeout Information
 Note, TIMEOUT_REREQUEST_SAFETY * TIMEOUT_RECV_REREQUEST is roughly how much time it takes to TIMEOUT a rerequest loop
 If absolutely no packets get received. Each time a successful rerequest comes through though, TIMEOUT_REREQUEST_SAFETY gets reset
 I feel 5 seconds total is generous, but for less reliable networks you might tweak these values

# Example setup:
 For a network with roughly 5 second latency between points, this might be more appropriate:
    TIMEOUT_REREQUEST_SAFETY = 10
    TIMEOUT_SYNC = 6
    TIMEOUT_RECV_LOOP = 8
    TIMEOUT_NO_WAIT = 0.05
    TIMEOUT_SEND_REREQUEST = 15
    TIMEOUT_RECV_REREQUEST = 3.5
 
