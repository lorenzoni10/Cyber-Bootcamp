## Solution Guide: Analyzing HTTP Data

The goal of this exercise was to practice analyzing captured HTTP packets. This exercise also emphasized the security risk presented by unencrypted HTTP traffic.

This activity required the following steps:

   - Opening a packet capture.
   
   - Creating a filter for HTTP traffic.
   
   - Isolating websites and the PHP webpages visited within those websites.
   
   - Analyzing `POST` requests for transmitted data.

---

First, open the packet capture in Wireshark by selecting `File` > `Open`.

- Determine the websites that were visited by Sally Stealer.  

  - Apply the filter to display HTTP `GET` requests by running the following:

     `http.request.method == "GET"`

- Scan the logs and look in the frame details. Review the various hosts under the HTTP dropdown. The results will be:

    - howtobeaspy.com
    - howtousebitcoin.com
    - acmecompany.yolasite.com
    - widgetcorp.yolasite.com

- Determine which PHP pages were visited on the websites.

  - Filter to display HTTP get requests for PHP pages by running the following:

     `http && frame contains "php HTTP"`

  The results will be:

  - `salesprojections.php`
  - `Intellectualproperty.php`

- Determine if Sally Stealer sent any communications. 

  - Filter to look for the `POST` command using:

     `http.request.method == "POST"`

  - Open the HTML Form URL under the HTTP data. The communication states:      

    _"This is Sally Stealer, I have the secret Sales Projections and Intellectual Property as we discussed. Please send me the 5 bitcoins as promised.  Hurry. Acme is starting to have suspicions."_

- Summarize the findings to determine if Sally Stealer has malicious intent.

    - Based on the websites Sally Stealer accessed and the message she sent to WidgetCorp, it's clear she is a spy trying to sell private data to Acme Corp's rival.
---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.