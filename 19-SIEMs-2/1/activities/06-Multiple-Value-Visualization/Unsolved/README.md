## Activity File: Multiple Value Visualization

- Your SOC staff was impressed with the radial gauge you designed to monitor attacks against the web server.

- They would like you create a visualization that displays the exact URL paths being targeted by attacks.

- You are tasked with designing a multiple value visualization to display the URL paths being targeted by the POST requests.

### Instructions

1. Design an SPL query with the following fields:
    - `source="radialgauge.csv"`
    - `http_method=POST`

    Add the `top` command to display the top 10 URI paths (`uri_path`).

2. Visualize the data in a pie chart.

3. Save your visualization as a report titled: "Pie Chart - Top 10 URI_PATH."

#### Bonus

- Test several other visualizations to see which might also be effective for displaying the top 10 URI paths.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  

