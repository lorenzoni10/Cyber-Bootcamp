# !/bin/bash

# This script will set up the instructor demo files and student activity files for Web Dev day 1
## You shouldn't need to use this script unless there are issues with the Vagrant machine.

# Create demo directory for instructor
sudo mkdir -p /home/instructor/Documents/demo
cd /home/instructor/Documents/demo

# Replace /etc/resolv.conf file to fix DNS issues around Docker pulls
sudo cat <<'EOF' > /etc/resolv.conf

# This file is managed by man:systemd-resolved(8). Do not edit.
#
# This is a dynamic resolv.conf file for connecting local clients to the
# internal DNS stub resolver of systemd-resolved. This file lists all
# configured search domains.
#
# Run "systemd-resolve --status" to see details about the uplink DNS servers
# currently in use.
#
# Third party programs must not access this file directly, but only through the
# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,
# replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 8.8.8.8
options edns0
search Home

EOF

# Download docker activity file
cat <<'EOF' > /home/instructor/Documents/demo/docker-compose.yml 

version: "3.3"

services:
  wordpress:
    image: wordpress:4.6.1-php5.6-apache
    restart: always
    ports:
      - 8080:80
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: exampleuser
      WORDPRESS_DB_PASSWORD: examplepass
      WORDPRESS_DB_NAME: exampledb
    volumes:
      - wordpress:/var/www/html
      - ./volume:/var/www/html/volume
    container_name: wp
    networks:
      app-net:

  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: exampledb
      MYSQL_USER: exampleuser
      MYSQL_PASSWORD: examplepass
      MYSQL_RANDOM_ROOT_PASSWORD: "1"
    volumes:
      - db:/var/lib/mysql
    container_name: db
    networks:
      app-net:

  ui:
    image: httpd:2.4
    ports:
      - 10000:80
      - 10001:80
      - 10002:80  
      - 10003:80
    volumes:
      - ./volume:/home
    networks:
      app-net:

networks:
  app-net:
    ipam:
      driver: default
      config:
        - subnet: "10.0.2.0/24"

volumes:
  wordpress:
  db:
  ui:
EOF

# Restart the docker service
sudo systemctl restart docker

# Gives instructor ownership of their files
chown -R instructor: /home/instructor/Documents/demo/

# Install Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb

sudo dpkg -i google-chrome-stable_current_amd64.deb

# Install Chrome extensions function
install_chrome_extension () {
  preferences_dir_path="/opt/google/chrome/extensions"
  pref_file_path="$preferences_dir_path/$1.json"
  upd_url="https://clients2.google.com/service/update2/crx"
  mkdir -p "$preferences_dir_path"
  echo "{" > "$pref_file_path"
  echo "  \"external_update_url\": \"$upd_url\"" >> "$pref_file_path"
  echo "}" >> "$pref_file_path"
  echo Added \""$pref_file_path"\" ["$2"]
}

# if ! which "google-chrome" ; then
#   wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub \
#   | sudo apt-key add -
#   echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' \
#   | sudo tee /etc/apt/sources.list.d/google-chrome.list
#   sudo apt-get update
#   sudo apt install google-chrome-stable
# else
#   echo Chrome already installed
# fi

# Extension positionals for function (first is from ext.  URL, second is ext. name)
# install_chrome_extension "cfhdojbkjhnklbpkdaibdccddilifddb" "Adblock Plus"
install_chrome_extension "hlkenndednhfkekhgcdicdfddnkalmdm" "Cookie-Editor"
# install_chrome_extension "pgjjikdiikihdfpoppgaidccahalehjh" "Speedtest by Ookla"

# Setup for sysadmin, Activity 3, Swapping Sessions

# Create directory for activity
mkdir -p  /home/sysadmin/Documents/docker_files/

# Docker-Compose file for Swapping Sessions Activity
cat <<'EOF' > /home/sysadmin/Documents/docker_files/docker-compose.yml
version: "3.3"

services:
  wordpress:
    image: wordpress
    restart: always
    ports:
      - 8080:80
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: exampleuser
      WORDPRESS_DB_PASSWORD: examplepass
      WORDPRESS_DB_NAME: exampledb
    volumes:
      - wordpress:/var/www/html

  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: exampledb
      MYSQL_USER: exampleuser
      MYSQL_PASSWORD: examplepass
      MYSQL_RANDOM_ROOT_PASSWORD: "1"
    volumes:
      - db:/var/lib/mysql

volumes:
  wordpress:
  db:
EOF

# Gives sysadmin ownership of their files
chown -R sysadmin: /home/sysadmin/Documents/docker_files/
