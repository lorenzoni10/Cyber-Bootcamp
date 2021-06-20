## Solution Guide: Implementing Security Controls

In this activity, you had to draft the final piece of recommendations submitted to GeldCorp.

There are multiple solutions. Below are some examples.

---  

Control suggestions: 

1. **Implement a turnstile**. The organization could implement turnstiles in all of its data centers. 
    - These turnstiles would only allow one person through at a time and require employees to scan an ID card to proceed. 

    - This requires installing the system at all sites, and issuing keycards to all employees, both of which have significant costs attached. 

    - However, a financial organization might deem the added security of such physical access controls worth the expense.
  
2. **Encrypt top-secret data**. The attacker wouldn't have been successful if they'd broken into the data facility and stolen _encrypted_ financial records. 
    - The organization could choose to encrypt all of its top-secret data, and only allow it to be decrypted by a single server, verified by digital signature. 
    
    - As an advanced suggestion, the company could then choose to allow access to that decrypted data via API, and restrict access to this API to only trusted individuals. This is a technical control.

These suggestions could be implemented _on top of_ or _separately from_, the training solution. **Stacking** solutions that address the problem in different ways strengthens your security perimeter and makes your system more robust to failure.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
