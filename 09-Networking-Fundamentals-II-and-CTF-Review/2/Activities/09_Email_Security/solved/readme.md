## Solution Guide: Email Security

In this activity, you continued to analyze the suspicious emails sent to the CFO of ACME Corp to determine which of the emails were spoofed.

Completing this activity required the following steps:

- Reviewing the headers in each email for indicators of spoofing. 
   
---


**Email One**

- Received-SPF: "Pass" indicates that it is an authorized sender on behalf of Microsoft.
- From: Jonathan Thomas <jonathanthomas@microsoft.com>—the email and name match.
- Summary: While there is no 100% guarantee that this is a legitimate email, the records in the header indicate it is safe.


**Email Two**

- Received-SPF: "Pass" indicates that it is an authorized sender on behalf of Yahoo.
- From: Michael Smith <xzvvvret34344@yahoo.com>—the name and email do not match and the email looks suspicious.
- Summary: While there is no 100% guarantee that this is a spoof email, the mismatch of the name makes it likely.

**Email Three**
- Received-SPF: "Fail" indicates that it is not from an authorized email provider.
- From: Timmy Tom <timmytom@widgets.com>—the name and email match. 
- Summary: While there is no 100% guarantee that this is a spoof email, the failed SPF record usually indicates a spoofed email. 

**Email Four**

- Received-SPF: "Fail" indicates that it is an not an authorized email provider for the IRS.
- From: IRS Assistance Programs  <m1T7pqweeqweD8G@thought.bestwebsitesabc.com>—the name and email do not match.
- Summary: While there is no 100% guarantee that this is a spoof email, the failed SPF record and the obvious mismatch of the from email address is a strong indicator this is a spoofed email. 


**Email Five**
- Received-SPF: "Pass" indicates this is an authorized sender for CompanyA. 
- From: Billy Bob <billybob@companyA.com>—the email and name match. 
- Summary: While there is no 100% guarantee that this is a legitimate email, the records in the header indicate it is safe.

An email fails the Received-SPF verification, but was a legitimate email.
    
  - What does this indicate?
  -  What would you recommend to prevent future emails from failing this validation?

This most likely indicates that the mail server sending emails on behalf of the domain doesnt have a DNS SPF record.

To resolve this, an SPF record should be added with the IP of the mail server sending these emails.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


