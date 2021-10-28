## Activity File: Geographic Map Visualization 

- OMP would like you to expand your visualizations to provide more geographic information about the attacks.  

- The Security team can use this information to create firewall rules that restrict traffic from certain geographic locations.

- You are tasked with designing a geographic map visualization to help your SOC team understand where attacks are originating.

### Instructions

1. Design a geographic map that displays a visualization of source IP address locations. Use the following fields:

    - `source="radialgauge.csv"`
    - `http_method=POST`

    **Hint:** Add `iplocation` and `geostats` to your query.
 
2. Save your visualization as a report titled: "Geographic Map - POST request monitor by Source IP."   
  
#### Bonus
  
- Modify the search to display in the same map the URIs being attacked.
  
  - **Hint:** Research how to modify the `geostats` command.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
