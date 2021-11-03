## Solution Guide: Part 2 - Defend Your SOC
   
### Windows Server Logs

#### Report Analysis for Severity

Did you detect any suspicious changes in severity?
	

- Yes. The percentages changed from:

	```
	High: 6%
	Informational: 93%
	```
	to: 
	```
	High: 20%
	Informational: 80%
	```

- This indicates an increase in the high severity cases.

#### Report Analysis for Failed Activities

Did you detect any suspicious changes in failed activities?

- Yes. The percentages changed from:
	```
	success: 97%
	failure: 3%
	```

	 to:
	```
	success: 98%
	failure: 1.5%
	```

- This indicates that there is not a major change in the cumulative failure of events. 
   
---
#### Alert Analysis for Failed Windows Activity

- Several of the answers are dependent on what the groups select for their baselines and thresholds.

- There is some potential suspicious activity for failed activity at 8 a.m. on Weds, March 25th.

- The count of activity is 35 events during this hour.
                
   
#### Alert Analysis for Successful Logons

- Several of the answers are dependent on what the groups select for their baselines and thresholds.

- There is some potential suspicious activity for failed activity at 11 a.m and 12 p.m. on Weds, March 25th.

- The count of activity is 196 at 11 a.m. and 77 at 12 p.m. 

- The primary user logging in is `user j`.

#### Alert Analysis for Deleted Accounts

Did you detect a suspicious volume of deleted accounts?  
	
- There was no suspicious activity of deleted accounts.
   
---
#### Dashboard Analysis for Time Chart of Signatures

- Does anything stand out as suspicious? What signatures stand out?
	- Yes, the signatures that have suspicious activity are: User account was locked out, attempt was made to reset a users password, and an account was successfully logged on.


- What time did it start and stop for each signature? What is the peak count of the different signatures?

	- User account was locked out: Started around 1 a.m. and ended at 3 a.m. on March 25th. The peak count was 896.

	- An attempt was made to reset a users password: Started around 9 a.m. and ended at 11 a.m. on March 25th. The peak count was 1,258.

	- The account was successfully logged on: Started around 11 a.m. and ended at 1 p.m. on March 25th. The peak count was 196.

 #### Dashboard Analysis for Users

- Does anything stand out as suspicious? Which users stand out?
	- Yes, the users that have suspicious activity are users `A`, `K`, and `J`.

- What time did it begin and stop for each user? What is the peak count of the different user?

	- `User A`: Started around 1 a.m. and ended at 3 a.m. on March 25th. Peak count was 985.

	- `User K`: Started around 9 a.m. and ended at 11 AM on March 25th.  Peak count was 1,256.

	- `User J`: Started around 11 a.m. and ended at 1 p.m. on March 25th. Peak count was 196.
	
    
#### Dashboard Analysis for Signatures with Bar, Graph, Pie Charts

- The suspicious findings should be similar to the time chart.
			
#### Dashboard Analysis for Users with Bar, Graph, Pie Charts

- The suspicious findings should be similar to the time chart.

#### **Dashboard Analysis for Users with Statistical Chart**   

- What would be the advantage/disadvantage of using this report, compared to the other user panels you created?

	- The answers can vary between groups, but one disadvantage of the stats chart compared to a time chart is that it shows a cumulative perspective, while a time chart shows suspicious activity over a more specific, shorter time frame.

     
---


### Apache WebServer Logs 
   
#### Report Analysis for Methods

- Did you detect any suspicious changes in HTTP methods? If so, which one?
	- Yes, there was a suspicious change in the HTTP POST method, which was raised from 1% to 29%.

- What is that method used for?

	- POST is used to submit or update information to a web server.
							
   
#### Report Analysis for Referrer Domains

- Did you detect any suspicious changes in referrer domains?
	
	- There were no suspicious referrers during the attack.

#### Report Analysis for HTTP Response Codes
- Did you detect any suspicious changes in HTTP response codes? 
									
	- There are several small changes, but the most prominent is the 404 response code, which increased from 2% to 15%.
    
---
#### Alert Analysis for International Activity

- Did you detect any suspicious volume of international activity? If so what was the count of the hour it occurred in?
	- There was activity in Ukraine at 8 p.m. on Weds, March 25th, and had a count of 1,369 events.

- The other answers are dependent on each group's baselines and thresholds.


#### Alert Analysis for HTTP POST Activity

- Did you detect any suspicious volume of HTTP POST activity? If so, what was the count of the hour it occurred in and when did it occur?

	- There was a spike in POST method activity at 8 p.m. on Weds, March 25th, and had a count of 1,296 events.

- The other answers are dependent on each group's baselines and thresholds.
 
---

#### Dashboard Analysis for Time Chart of HTTP Methods
  
- Does anything stand out as suspicious?
	- Yes, there were suspicious activities of the POST and GET method.

- What was the method that seems to be used in the attack? What time did it begin and end, and what was the peak count?
	-  The POST method was used, starting at 8 p.m. and ending at 9 p.m. The peak count was 1,296.

	- THE GET method was used, starting at 6 p.m. and ending at 7 p.m. The peak count was 729.
    
 #### Dashboard Analysis for Cluster Map
  
- Does anything stand out as suspicious? What new country, city on the map has a high volume of activity?
	- Yes, there is suspicious activity in Ukraine.

- What is the count of that country, city?
	- When zoomed in, we can see the cities in Ukraine are: 
		- Kiev: Count of 872	
		- Kharkiv: Count of 432
                    
    
#### Dashboard Analysis for URI Data
- Does anything stand out as suspicious? What URI is being hit the most?

	- Yes, there is suspicious activity against the main VSI logon page: `/VSI_Account_logon.php`.

- Based on the URI being accessed, what could the attacker potentially be doing?	
	- The attacker may be trying to brute force the VSI logon page.

---
    

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
