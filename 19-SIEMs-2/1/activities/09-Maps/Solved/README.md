## Solution Guide: Geographic Map Visualization 

In this activity you were tasked with designing a geographic map using the `iplocation` and `geostats` commands.

---

1. Design a geographic map that displays a visualization of source IP address locations. 
   - `source="radialgauge.csv" http_method=POST| iplocation src_ip | geostats count`

    In the Visualization tab, select the cluster map visualization type.  

2. Save your visualization as a report titled: "Geographic Map - POST request monitor by Source IP."

**Bonus** 

- Modify the search to display in the same map the URIs being attacked: 

  - `source="radialgauge.csv" http_method=POST| iplocation src_ip | geostats count by uri_path`  
 
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
