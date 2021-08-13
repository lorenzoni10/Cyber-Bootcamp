## Solution Guide: Footprinting with `traceroute`

The goal of this exercise was to practice using the ping utility `traceroute` to determine specific points of failure in network transmissions.

Completing this activity required the following steps:

   - Running `traceroute` against the rejected host IP addresses.
   
   - Analyzing the `traceroute` responses to determine at which point in a transmission a failure occurred.
   
   - Visualizing the `traceroute` path using a Traceroute Mapper tool.
	
  --- 

Open up a Linux terminal to run the ping commands.
  	 
 Run `traceroute` against the IP addresses from the last activity that returned a failed response.

- The IPs that had a failed response were:
	
	- `41.19.96.234 `
	- `154.226.18.4` 
	- `176.56.238.99`

- To run traceroute on Linux with ICMP mode: 
  - Run `sudo traceroute -I 41.19.96.234`

Determine where in their transmission (at which hop) the transmission failed.
     
- The responses will likely be different as each class is on a different network. Here is a sample response for reference:

  ```bash
  traceroute to 41.19.96.234 (41.19.96.234), 30 hops max, 60 byte packets
   1  _gateway (10.0.2.2)  0.117 ms  0.088 ms  0.081 ms
   2  192.168.1.1 (192.168.1.1)  1.764 ms  1.677 ms  1.623 ms
   3  * * *
   4  096-034-073-234.res.spectrum.com (12.34.56.234)  16.090 ms  16.960 ms  17.053 ms
   5  cts01nwnnga-tge-3-0-0.nwnn.ga.charter.com (12.34.78.239)  16.843 ms  16.852 ms  16.899 ms
   6  dtr01nwnnga-tge-0-1-0-6.nwnn.ga.charter.com (12.34.78.238)  16.933 ms  9.163 ms  14.229 ms
  ```

Document a summary of your findings using a [Traceroute Mapper tool](https://stefansundin.github.io/traceroute-mapper/). 

- Copy and paste the `traceroute` results and place them in the top field on the website: stefansundin.github.io/traceroute-mapper.

- Click `Map it!`

   
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
