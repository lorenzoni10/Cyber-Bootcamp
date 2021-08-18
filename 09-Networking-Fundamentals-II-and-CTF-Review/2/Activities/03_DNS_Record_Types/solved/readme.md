## Solution Guide: Analyzing DNS Record Types

In this activity, you used `nslookup` to analyze multiple DNS records for several domains, and answered several questions about your findings. 

Completing this activity required the following steps:

- Using `nslookup` for three domains. 

- Determining several DNS records types for each domain.

- Analyzing your findings. 
   
---

**splunk.com** 

  - **A record**: 
    - Run `nslookup -type=A splunk.com`
      
    - Results: 
      
    ```
    Name:    splunk.com
    Addresses:  35.153.82.195
                52.5.196.118

    ```
      
   - **NS record**: 

      - Run `nslookup -type=NS splunk.com`
    
      - Results:
    
      ```
      splunk.com      nameserver = ha2.markmonitor.zone
      splunk.com      nameserver = ha4.markmonitor.zone
      splunk.com      nameserver = ha1.markmonitor.zone
      splunk.com      nameserver = ha3.markmonitor.zone

      ```
    
  - **MX record**:

    - Run `nslookup -type=mx splunk.com`

    - Results:

      ```
      splunk.com      MX preference = 20, mail exchanger = mx1.splunk.iphmx.com
      splunk.com      MX preference = 20, mail exchanger = mx2.splunk.iphmx.com

      ```

**fireeye.com**

- **A record**: 

  - Run `nslookup -type=A fireeeye.com`
  
  - Results: 
  
    ```
      Name:    fireeeye.com
      Address:  103.224.182.244

    ```

- **NS record**: 

  - Run `nslookup -type=NS fireeye.com`
  
  - Results:
  
    ```  
    fireeye.com     nameserver = chuck.ns.cloudflare.com
    fireeye.com     nameserver = bonnie.ns.cloudflare.com

    ```

- **MX record**: 

  - Run `nslookup -type=mx fireeye.com`

  - Results: 
  
    ```  
      fireeye.com     MX preference = 40, mail exchanger = alt3.us.email.fireeyecloud.com
      fireeye.com     MX preference = 10, mail exchanger = primary.us.email.fireeyecloud.com
      fireeye.com     MX preference = 20, mail exchanger = alt1.us.email.fireeyecloud.com
      fireeye.com     MX preference = 30, mail exchanger = alt2.us.email.fireeyecloud.com

    ```


**nmap.org**

- **A record**: 
  - Run `nslookup -type=A nmap.org`.
  
  - Results: 
    
    ```
    Name:    nmap.org
    Address:  45.33.49.119
    ```

- **NS record**: 

  - Run `nslookup -type=NS nmap.org`.
  
  - Results:
      
    ```  
      nmap.org        nameserver = ns4.linode.com
      nmap.org        nameserver = ns1.linode.com
      nmap.org        nameserver = ns2.linode.com
      nmap.org        nameserver = ns3.linode.com
      nmap.org        nameserver = ns5.linode.com
    ```
  
- **MX record**: 
  - Run `nslookup -type=mx nmap.org`.

  - Results: 
    
    ```
     nmap.org        MX preference = 5, mail exchanger = ALT1.ASPMX.L.GOOGLE.COM
     nmap.org        MX preference = 1, mail exchanger = ASPMX.L.GOOGLE.COM
     nmap.org        MX preference = 5, mail exchanger = ALT2.ASPMX.L.GOOGLE.COM
     nmap.org        MX preference = 10, mail exchanger = ASPMX3.GOOGLEMAIL.COM 
     nmap.org        MX preference = 10, mail exchanger = ASPMX2.GOOGLEMAIL.COM
    ```


Did any of the domains have more than one MX record? If so, why do you think that is? 

  - All of the domains have more than one MX record. It's useful to have more than one MX record as a backup in case one isn't available, or to provide load balancing for large volumes of emails.

For nmap.org, list the mail servers, from the highest to lowest priority.

- The servers are ordered by MX preference below. The servers with the same MX preference have the same priority.

  ```
  (HIGHEST) nmap.org        MX preference = 1, mail exchanger = ASPMX.L.GOOGLE.COM
            nmap.org        MX preference = 5, mail exchanger = ALT1.ASPMX.L.GOOGLE.COM
            nmap.org        MX preference = 5, mail exchanger = ALT2.ASPMX.L.GOOGLE.COM
            nmap.org        MX preference = 10, mail exchanger = ASPMX3.GOOGLEMAIL.COM 
  (LOWEST)  nmap.org        MX preference = 10, mail exchanger = ASPMX2.GOOGLEMAIL.COM
  ```


Look up the SPF record for nmap.org
- The DNS query to look up the SPF record is:

  `nslookup -type=txt nmap.org`

- The results are:
  
  ```
          "v=spf1 a mx ptr ip4:45.33.49.119 ip4:173.255.243.189 ip4:192.81.131.254 ip6:2600:3c01::f03c:91ff:fe98:ff4e ip6:2600:3c01::f03c:91ff:fe70:d085 include:_spf.google.com ~all"
  ```
  
  This specifies the range of IPs allowed to send emails on behalf of nmap.org

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
