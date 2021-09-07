### Alternate Hostname Testing Activity

The XCorp Red Team has been using the new DVWA setup to train new hires and use for general testing.

You have been asked to test the load balancer once more to make sure traffic is being distributed among all 3 of your VM's.

In this activity, you will exploit a vulnerability in DVWA to determine what machine you are connected to. 

You are tasked with collecting the hostnames for each DVWA container and then verifying that the load balancer is sending traffic to different containers as needed.

### Instructions

Start by gathering the hostname of each of the DVWA containers that your WebVM's are running. 

- SSH from your jumpbox to a Web VM
- Connect to the DVWA container
- Run the command `hostname` to get the hostname
- For each of your Web VM's make a note of the following:
	- The VM Name from Azure: `Web-1`, `Web-2`, `Web-3`, etc.
	- The Internal IP of the VM: `10.0.0.5` etc.
	- The hostname of the DVWA container that is running on that VM. 
		- **Hint:** The hostname of a container will be the container's identifier and resemble the following: `6831a670b43e`

After you have the info for each VM, navigate to the DVWA site and set it up to test.

Setup DVWA:
- Navigate to: `http:[load-balancer-ip]/setup.php`
- Scroll to the bottom of the page and click on `Create/Reset Database`.
- Click on login and use the credentials `admin:password`.
- Click on `Command Injection` on the left side of the page.

Exploit DVWA to determine what host you are connected to:

- Run a command that gives you the hostname of the container you are currently connected to.

- Go to Azure and stop that VM.

- Run the same command again to get the hostname of the container you are now connected to.

- Make a note of what container you now connected to. 

- Try a few more scenarios of getting the hostname and shutting down VM's to see this hostname change.

**NOTE:** When the load balancer starts to send your traffic to another VM that you have not yet connected to, you may be returned to the login screen and not be able to login. Remember that you haven't yet setup that instance of DVWA, because you are now connected to a different machine. Return to instructions labeled: 'Setup DVWA' to get logged in and continue testing. Once these steps have been completed for each instance, the load balancer can switch the VM in the background without logging you out.
