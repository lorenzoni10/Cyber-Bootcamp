###############################################################################
# Demo
# Staging for removal demo
choco install -y itunes vlc
# Steam was part of this list but it kept needing to update

# Create CSV herestring of choco remove demo
$chocodemoString = @'
name,description
itunes,"Apple's music application"
vlc,"An application for encoding and playing videos"
'@

# Stage demo directory for choco sections
New-Item -Path "C:\Users\azadmin\Documents\Demo\choco\" -ItemType "Directory" -Force
# Stage demo CSV file
New-Item -Path "C:\Users\azadmin\Documents\Demo\choco\chocodemo.csv" -ItemType "File" -Value $chocodemoString -Force

###############################################################################
# Activity
# Staging for removal activity
choco install -y mumble spotify skype teamviewer icloud flashplayeractivex flashplayerppapi uplay telegram

# Create CSV herestring of choco packages
$chocoactivityString = @'
name,description
mumble,"A voice chat application"
spotify,"An online music player"
telegram,"A cloud-based instant messenger"
skype,"An application for online calling"
teamviewer,"An application for remotely connecting to another computer"
icloud,"Apple's cloud-syncing application"
flashplayeractivex,"An Internet Explorer/Edge add-on that allows one to view Flash animations and videos"
flashplayerppapi,"Chrome/Chromium's implementation of the Adobe Flash Player Plugin"
uplay,"The Ubisoft game launcher"
'@

# Stage activity directory for choco remove activity
New-Item -Path "C:\Users\azadmin\Documents\Activity\choco\" -ItemType "Directory" -Force

# Stage activity CSV file
New-Item -Path "C:\Users\azadmin\Documents\Activity\choco\chocoactivity.csv" -ItemType "File"  -Value $chocoactivityString -Force