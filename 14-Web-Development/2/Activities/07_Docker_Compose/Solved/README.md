## Solution Guide: Deploying and Testing a Container Set

This activity required students to use Docker-Compose to deploy a container set and confirm functionality. 

---

1. First, deploy the microservices:

    - Navigate to your `/home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_activity` directory.

    - Deploy the WordPress stack with `docker-compose up`.
    
    - Verify the site is running by navigating to `192.168.2.2` in the browser.

2. In a new terminal window, verify that the application runs properly by completing the following:

    - Use an interactive bash session to enter the container: `sudo docker exec -it db bash` 

    - Verify that the MySQL credentials provided in the `docker-compose.yaml` file are functional with `mysql -u [username] -p[password]`.

      - Read the `docker-compose.yml` file to find the username and password. 
        - Run: `mysql -u demouser -p`
        - Run: `demopass`

    - Exit the MySQL session by entering `exit`, exit the interactive bash session, and press Ctrl+C in the terminal where you ran `docker-compose up` to stop the Docker Compose stack.

3. Change the IP address and redeploy:

    - Make sure your deployment configurations are cleared with `sudo docker-compose down`.

    - Edit the `docker-compose.yml` file in the `stack` directory so that it has the new `ui1` IP address as seen below.

      ```YAML
        ui1:
          container_name: wp
          image: httpd:2.4
          ports:
            - 10001:8080
          volumes:
            - ./volume:/home
          networks:
            demo-net:
              ipv4_address: 192.168.2.200
      ```

    - Redeploy the stack with `docker-compose up`.

    - Open your browser and navigate to `192.168.2.200` to see the site at the newly mapped IP address.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
