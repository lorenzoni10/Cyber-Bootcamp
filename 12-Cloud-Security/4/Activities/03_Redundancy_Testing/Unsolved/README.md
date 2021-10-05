## Activity File: Redundancy Testing

- Over the last few days, you configured a vulnerable web application server for XCorp's Red Team to train new hires and use for general testing.

- In this activity, you will finalize this setup by putting a second VM behind your load balancer and testing for redundancy. 

- You are tasked with adding your latest VM to the backend pool for your load balancer and testing whether the website continues working if one of your VMs has a problem.

### Instructions

1. Add your new VM to the backend pool for your load balancer.

2. Verify that the DVWA site is up and running and can be accessed from the web.

3. Turn off one of your VMs from the Azure portal.
    - Confirm if you can still access the DVWA website.

4. Turn off the other VM. 
    - Verify that the DVWA site stops working.

5. Boot up the VM that you first shut down, so it is running by itself.
    - Confirm if you can access the DVWA site.

6. Boot up the second VM.
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
