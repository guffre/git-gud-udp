# git-gud-udp
An attempt at reliable UDP transfer with fairly low overhead. Stores data in memory as a dict to maintain order, so dont send too large a file.

# Packet Info
 [CHECKSUM]([PACKET_NUMBER][DATA])
 
 Currently, checksum is implemented as an MD5 hash of PACKET_NUMBER+DATA
 Packets are randomly sized between MIN_DATA_SIZE and MAX_DATA_SIZE.
 
 NOTE: The gudp protocol attempts to automatically handle sizes for you, so theres no need to specify size when `send()`ing or `recv()ing`. That said, a single `send()/recv()` gets stored in memory so your program should chunk data if youre sending/recieving something exceptionally large.
 
 # Example Usage
 ## Client:
     s = gudp("127.0.0.1", 8000)
     data = <arbitrary amount of data> # Ive tested with 60mb+
     s.send(data)
 
 ## Server:
      s = gudp("0.0.0.0", 8000, True)
      while True:
          data = s.recv()
          if data:
              print(data)
