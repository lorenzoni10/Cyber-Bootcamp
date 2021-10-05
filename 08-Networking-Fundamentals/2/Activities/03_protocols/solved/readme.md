## Solution Guide: Interpreting Protocols

Completing this activity required the following steps:

   - Opening the log file to view the various log records.

   - Using a web tool to convert the binary data to readable text.

   - Analyzing the data from the text to determine the protocol being used.
	
---

Open the log file and note that it contains multiple log records.

Convert the binary data for each log record to a readable format with a web tool of your choosing.	
	 
  - There are many web tools available for converting binary data to readable text. An easy-to-use tool is the
	  [String Functions Binary To String Converter](http://string-functions.com/binary-string.aspx).
	  
    
  -  Go to the site, copy the binary log records, one at a time, into the top field, and click "Convert!"
	  
	  

**Log Record 1**

Log Record 1 after converting:

```
  GET / HTTP/1.1
  Host: widgets.com
  Connection: keep-alive
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
  Accept-Encoding: gzip, deflate
  Accept-Language: en-US,en;q=0.9,nb;q=0.8
```

  - The protocol is **HTTP**.


**Log Record 2**
   
	
Log Record 2 after converting:
```
  File Transfer Protocol (FTP)
    230 Login successful.\r\n
        Response code: User logged in, proceed (230)
        Response arg: Login successful.
```

  - The protocol is **FTP**.
	

**Log Record 3**
              
 Log Record 3 after converting:

```
TLSv1.2 Record Layer: Application Data Protocol: http-over-tls
    Content Type: Application Data (23)
    Version: TLS 1.2 (0x0303)
    Length: 56
    Encrypted Application Data: d03ff41452da9e9c3ec76cbeb35e8ffc1f64bf80f512924a?
```    

- The protocol of **TLS** or **HTTP** would both be acceptable answers, as https-over-tls is https. 
 
**Log Record 4**

Log Record 4 after converting:
 
 ```
 Domain Name System (query)
    Transaction ID: 0x18b6
    Flags: 0x0100 Standard query
        0... .... .... .... = Response: Message is a query
        .000 0... .... .... = Opcode: Standard query (0)
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... .0.. .... = Z: reserved (0)
        .... .... ...0 .... = Non-authenticated data: Unacceptable
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        applegate.com: type A, class IN
    [Response In: 623]    
```

- The protocol is **DNS (Domain Name System)**. 


**Log Record 5**   
              
Log Record 5 after converting:

```
 Address Resolution Protocol (request)
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    Sender MAC address: Technico_65:1a:36 (88:f7:c7:65:1a:36)
    Sender IP address: 10.0.0.1
    Target MAC address: 00:00:00_00:00:00 (00:00:00:00:00:00)
    Target IP address: 10.0.0.6`
```    

- The protocol is **ARP (Address Resolution Protocol)**.   

**Bonus Log Record**

Bonus Log Record after converting:

``` 
HCI H4
    [Direction: Unspecified (0xffffffff)]
    HCI Packet Type: HCI Command (0x01)
HCI Command - Read Local Supported Features
    Command Opcode: Read Local Supported Features (0x1003)
    Parameter Total Length: 0
    [Response in frame: 4]
    [Command-Response Delta: 4.181ms]
```    
  - HCI stands for **Host Controller Interface** which is used by Bluetooth.

---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
