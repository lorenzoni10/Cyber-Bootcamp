## Solution Guide:  Single Value Visualizations
      
In this activity, you were tasked with designing a radial gauge to illustrate the severity of a single value.

--- 

1.  Upload the radialgauge.csv file to your local Splunk system located in the splunk/logs/Week-2-Day-1-Logs directory. Select all defaults during the upload process.

2.  Design a search to view the POST events:

    - `source="radialgauge.csv" http_method=POST |stats  count as total`
   

3. Design a radial gauge to visualize the data. 
  
    - Select **Visualization** > **Radial Gauge**.

    - Change the ranges of the radial gauge by selecting **Format** > **Color Ranges** > **Manual**.

      The ranges can vary, as long as 1,200 POST requests per hour is in the red range.

      - For example:
        - Green: 0-400
        - Yellow: 400-1,000
        - Red: 1,000-2,000

4. Save your visualization as a report titled: "Radial Gauge - POST request monitor."   

Once you save, the radial gauge should display.

BONUS: Design an alert to trigger when the the count reaches the red range.

  - `This will vary from student to student depending on the ranges each student selects.`
  - `The bonus is correct if an alert is designed to trigger when the count of events reaches the lower part of the red range selected in step 3.`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
