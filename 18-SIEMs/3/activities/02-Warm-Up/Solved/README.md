## Solution Guide: Splunk Warm Up 

In this activity, you had to design a custom SPL query and research specific security mitigation strategies for an attack.

---

1. Upload the provided log file.

2. Determine the top source IP address (`src_ip`).

    - The top `src_ip`, with a count of 22, is `41.146.8.66`.

3. Determine the primary attack name (`attack_name`) in the logs.

   - The top, and only, `attack_name` is `Oracle.9i.TNS.OneByte.DoS`.

4. Answer the following questions:

    - Fortinet logs are from which type of device?

      - These logs are from an intrusion prevention system. The vendor's name is Fortinet.

    - What is the city and country of the top source IP address?

      - Using any online geo-lookup tool, we can learn that the IP is from Pretoria, South Africa.

    - Provide a brief summary of the `attack_name` found:
      - According to the [Fortigaurd website]( https://fortiguard.com/encyclopedia/ips/10725/oracle-9i-tns-onebyte-dos), this attack is a denial of service attack against a TNS listener. A TNS listener manages the traffic for a database.

    - What is a recommended mitigation for the attack?

      - According to the same website, one mitigation is to apply patching or upgrade to a non-vulnerable version.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  