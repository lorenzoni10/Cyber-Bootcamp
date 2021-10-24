## Solution Guide: Rule Correlation

The goal of this activity was to develop a correlation rule to assist with determining if a security related event has occurred.

---

1. Create an alert when:
    - The protocol is HTTP.
    - The HTTP response code is not 200.
    - The source IP is from Beijing.
   
2. Create an alert when:
    - The protocol is HTTP.
    - The same source IP appears more than 50 times within 5 minutes.
    - This is an estimate and the true setting may be adjusted depending on past attacks.
   
3. Create an alert when:
    - The protocol is HTTP.
    - The response code is 200.
    - The resource contains .jpg in the file name.
    - The IP address is not from the United States.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  