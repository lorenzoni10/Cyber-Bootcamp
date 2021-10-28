## Activity File: Single Value Visualizations

This week, you will continue to play the role of SOC manager at Omni Military Products (OMP). 

- The Networking team notified you about performance issues that OMP's public-facing website experienced over the weekend.

- The team discovered that these issues were caused by an attacker flooding the web server with POST requests.

- As the SOC manager, you would like to build visualizations that your SOC team can use to determine the severity of the attack. These visualizations will help your SOC quickly and accurately respond to attacks.

- Your networking team provided you with a log file of two hours of normal activity for you to analyze.

- You are tasked with designing a single value radial gauge to assist with monitoring attacks against your website.




### Instructions

1. Upload the `radialgauge.csv` file to your local Splunk system located in the splunk/logs/Week-2-Day-1-Logs directory.  Select all defaults during the upload process.


2. Within Splunk design a search to view the POST events for the time range of "All TIME", using the following fields:
    - `source="radialgauge.csv"`
    - `http_method=POST`
    - `stats count as total`
  
3. Design a radial gauge to visualize the data. 

   - Your Networking team notified you that they received approximately 1,200 POST requests during a 2 hour period of the attack. 

      Design a radial gauge with the following criteria:
   
      - Count of total POST requests

      - Three different color settings: green, yellow, and red.
         - Select the appropriate ranges for each color setting, use your best judgement!
         - *Hint: The logs you have loaded are considered normal activity.*
       
4.  Save your visualization as a report titled: "Radial Gauge - POST request monitor."            
       
#### Bonus

- Design an alert to trigger when the the count reaches the red range.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
