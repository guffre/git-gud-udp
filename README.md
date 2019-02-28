# git-gud-udp
An attempt at reliable UDP transfer with fairly low overhead. No dependencies, written in 2.7
I was informed this appears to be an implementation of Selective Repeat Error Recovery, so it should be pretty dependable!

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
     data = <arbitrary amount of data>
     s.send(data)
 
 ## Server:
      s = GGUdp("0.0.0.0", 8000)
      s.bind()
      while True:
          data = s.recv()
          if data:
              print(data)
