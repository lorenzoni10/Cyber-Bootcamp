## Solution Guide: Footprinting with `ping`

In this activity, you had to use `ping` to determine which of CompuCom's host IP addresses are accepting connections.

This activity required the following steps:

   - Sending a `ping` request to several IP addresses.
   
   - Analyzing the `ping` responses to determine which hosts are available.

   - Crafting an `fping` request to send multiple pings in a single command.

---

Run a `ping` request against each of the following IP addresses:

- `192.0.43.10`
- `107.191.96.26`
- `41.19.96.234`
- `107.191.101.180`
- `23.226.229.4`
- `154.226.18.4`
- `176.56.238.3`
- `176.56.238.99	`


**Note:** Results may differ since this is a live network ping.

- The command to run the pings will look like:

    `$ ping 192.0.43.10`

- All the IPs except the three listed below will return a successful result:

``` bash
Pinging 192.0.43.10 with 32 bytes of data:
Reply from 192.0.43.10: bytes=32 time=75ms TTL=241
Reply from 192.0.43.10: bytes=32 time=29ms TTL=241
Reply from 192.0.43.10: bytes=32 time=44ms TTL=241
Reply from 192.0.43.10: bytes=32 time=30ms TTL=241

Ping statistics for 192.0.43.10:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 29ms, Maximum = 75ms, Average = 44ms`

```
    
- The three IPs that fail are:

    - `41.19.96.234` 
    - `154.226.18.4 `
    - `176.56.238.99`

-  The result failure will look like:

```bash 
Pinging 41.19.96.234 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 41.19.96.234:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),`    
```

Use `fping` to ping all of the IP addresses in a single command.

- The command is: 
	
`fping 192.0.43.10 107.191.96.26 41.19.96.234 107.191.101.180 23.226.229.4 154.226.18.4 176.56.238.3 176.56.238.99`
  
- The result will look like:

```bash
192.0.43.10 is alive
107.191.101.180 is alive
107.191.96.26 is alive
23.226.229.4 is alive
176.56.238.3 is alive
41.19.96.234 is unreachable
154.226.18.4 is unreachable
176.56.238.99 is unreachable
```
 
**Bonus**

Use `fping` to ping the range of IPs from  `107.191.96.26` to `107.191.96.32`.

- The command is: 
	
    `fping -s -g 107.191.96.26 107.191.96.32`
  
- Because these are live addresses, the result will look similar to:

```bash
107.191.96.26 is alive
107.191.96.27 is alive
107.191.96.31 is alive
107.191.96.32 is alive
107.191.96.29 is alive
107.191.96.30 is alive
107.191.96.28 is unreachable

       7 targets
       6 alive
       1 unreachable
       0 unknown addresses

       1 timeouts (waiting for response)
      12 ICMP Echos sent
       6 ICMP Echo Replies received
       0 other ICMP received

 49.2 ms (min round trip time)
 130 ms (avg round trip time)
 486 ms (max round trip time)
        4.120 sec (elapsed real time)
```


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.