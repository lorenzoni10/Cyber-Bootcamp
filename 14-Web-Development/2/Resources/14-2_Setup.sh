# !/bin/bash

# This script created from tinyurl.com/web-setup

# Ensure `sudo` is being used to run the script.
if [ "$(id -u)" != "0" ]; then
   echo "Please re-run this script, $0, with sudo!" 1>&2
   exit 1
fi

# docker-compose down Day 1 WordPress site
cd /home/sysadmin/Documents/docker_files/
docker-compose down

# Create directories for instructor and student
mkdir -p /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/
mkdir -p /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/
mkdir -p /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_demo
mkdir -p /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_demo
mkdir -p /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_activity
mkdir -p /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_activity
mkdir -p /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/falco_demo
mkdir -p /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/falco
echo 'directories created'

# Download and install docker-compose upgrade
# Reinstall docker-compose
curl -L "https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
echo 'docker-compose set up'

# Download docker files for demo
cat <<EOF > docker-compose.yml
version: "3.3"

services:
  ui:
    container_name: demo-ui
    image: httpd:2.4
    ports:
      - 10000:8080
    volumes:
      - ./volume:/home
    networks:
      demo-net:
        ipv4_address: 192.168.1.2
  db:
    container_name: demo-db
    image: mariadb:10.5.1
    restart: always
    environment:
      MYSQL_DATABASE: demodb
      MYSQL_USER: demouser
      MYSQL_PASSWORD: demopass
      MYSQL_RANDOM_ROOT_PASSWORD: "1"
    volumes:
      - db:/var/lib/mysql
    networks:
      demo-net:
        ipv4_address: 192.168.1.3
networks:
  demo-net:
    ipam:
      driver: default
      config:
        - subnet: "192.168.1.0/24"
volumes:
  ui:
  db:
EOF

cp -f docker-compose.yml /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_demo/
mv -f docker-compose.yml /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_demo/
echo 'docker-compose.yml demo files copied'

# Download docker activity file
cat <<EOF > docker-compose.yml
version: "3.3"

services:
  ui1:
    container_name: wp
    image: httpd:2.4
    ports:
      - 10001:8080
    volumes:
      - ./volume:/home
    networks:
      demo-net:
        ipv4_address: 192.168.2.2

  ui2:
    container_name: wp2
    image: httpd:2.4
    ports:
      - 10002:8080
    volumes:
      - ./volume:/home
    networks:
      demo-net:
        ipv4_address: 192.168.2.3

  ui3:
    container_name: wp3
    image: httpd:2.4
    ports:
      - 10003:8080
    volumes:
      - ./volume:/home
    networks:
      demo-net:
        ipv4_address: 192.168.2.4

  ui4:
    container_name: wp4
    image: httpd:2.4
    ports:
      - 10004:8080
    volumes:
      - ./volume:/home
    networks:
      demo-net:
        ipv4_address: 192.168.2.5

  db:
    container_name: db
    image: mariadb:10.5.1
    restart: always
    environment:
      MYSQL_DATABASE: demodb
      MYSQL_USER: demouser
      MYSQL_PASSWORD: demopass
      MYSQL_RANDOM_ROOT_PASSWORD: "1"
    volumes:
      - db:/var/lib/mysql
    networks:
      demo-net:
        ipv4_address: 192.168.2.6
networks:
  demo-net:
    ipam:
      driver: default
      config:
        - subnet: "192.168.2.0/24"
volumes:
  ui:
  db:
EOF
cp -f docker-compose.yml /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_activity/
mv -f docker-compose.yml /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_testing_activity/
echo 'docker-compose.yml activity files copied'

# # Install trivy script
# sudo wget https://github.com/aquasecurity/trivy/releases/download/v0.5.3/trivy_0.5.3_Linux-64bit.deb
# sudo chmod +x https://github.com/aquasecurity/trivy/releases/download/v0.5.3/trivy_0.5.3_Linux-64bit.deb
# sudo dpkg -i https://github.com/aquasecurity/trivy/releases/download/v0.5.3/trivy_0.5.3_Linux-64bit.deb
# sudo apt install aptitude
# aptitude install trivy
# rm -f trivy_0.5.3_Linux-64bit.deb

#Install trivy script
cat <<'EOF' > /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/trivy.sh
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
EOF
# install trivy
chmod +x /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/trivy.sh
/home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/trivy.sh
apt-get update -y 
apt-get install -y trivy
echo 'trivy installed'
# Clean up trivy.list file
awk '!x[$0]++' /etc/apt/sources.list.d/trivy.list > /tmp/trivy.list_bak
cp -f /tmp/trivy.list_bak /etc/apt/sources.list.d/trivy.list
echo 'trivy repo cleaned'

# Download and make falco.sh executable 
cat <<EOF > falco.sh
sudo falco service stop #if installed locally on Linux as a non-container
docker container rm falco
# Uncomment the following for the latest version of falco (might be incompatible)
# docker pull falcosecurity/falco
# docker run -i -t \
#     --name falco \
#     --privileged \
#     -v /var/run/docker.sock:/host/var/run/docker.sock \
#     -v /dev:/host/dev \
#     -v /proc:/host/proc:ro \
#     -v /boot:/host/boot:ro \
#     -v /lib/modules:/host/lib/modules:ro \
#     -v /usr:/host/usr:ro \
#     falcosecurity/falco

docker run \
  --interactive \
  --privileged \
  --tty \
  --name falco \
  --volume /var/run/docker.sock:/host/var/run/docker.sock \
  --volume /dev:/host/dev \
  --volume /proc:/host/proc:ro \
  --volume /boot:/host/boot:ro \
  --volume /lib/modules:/host/lib/modules:ro \
  --volume /usr:/host/usr:ro \
  falcosecurity/falco:0.19.0
EOF

# Executable falco and transfer
chmod +x falco.sh
cp -f falco.sh /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/falco_demo
mv -f falco.sh /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/falco
echo 'falco set up for instructor and sysadmin accounts'

# File ownership
chown -R instructor: /home/instructor/Cybersecurity-Lesson-Plans/14-Web_Dev/
chown -R sysadmin: /home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/
echo 'instructor and sysadmin users given ownership of respective files'

# Install jq
apt install jq -y
echo 'jq installed'

# Restart Docker service
systemctl restart docker
echo 'Docker service restarted'