## Solution Guide: Network Addressing
To complete this activity, you had to: 

- Convert binary traffic into IP addresses.

- Determine if they were public or private addresses. 

- Compare the IPs to a list of Acme's servers to see which systems the hacker was attempting to access.

---

IP Address 1:

- Use the [Browserling web tool](https://www.browserling.com/tools/bin-to-ip) to convert the numeric IP representation of `11000000101010000100010110010001` to `192.168.69.145`.

- This is a private IP address and falls in the network range of Acme Trade Secrets.

IP Address 2:


- The numeric IP representation of `00001010000000000000000000101010` is `10.0.0.42`.

- This is a private IP address and falls in the network range of Acme Trade Secrets.

IP Address 3:


- The numeric IP representation of `11000000101011000100010110010001` is `192.172.69.145`.

- This is a public IP address and falls in the network range of Acme Trade Secrets.

IP Address 4:

- The numeric IP representation of `00101001001011011011011000100000` is `41.45.182.32`.

- This is a public IP address and falls in the network range of Acme Intellectual Property Secrets.

IP Address 5:

- The numeric IP representation of `00001010000000000000000001001100` is `10.0.0.76`.

- This is a private IP address, and falls in the network range of Acme Trade Secrets.

Final Summary


- Based on the findings, the hacker is primarily trying to access Acme Corp's trade secrets as well as a server containing data for intellectual property.

Bonus

- The binary data of `100010001111011111000111011001010001101000110110` is actually a binary representation of a physical MAC Address. 

- This is likely the MAC address of the machine that the hacker is trying to access, or even the machine belonging to the hacker.  

- MAC addresses are displayed in hex, so this needs to be converted with a binary to hex converter, such as the one available here: [Rapid Tables Binary to Hex Converter](https://www.rapidtables.com/convert/number/binary-to-hex.html). 
 
- When converted, the hex representation is: `88F7C7651A36`    or  `88:F7:C7:65:1A:36`.

