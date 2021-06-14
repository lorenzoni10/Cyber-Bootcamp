#!/bin/bash

# Resolves last component of script path regardless of where it's being called
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done

DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

cd "$DIR"

# Assumed home directories
WIN_DIR="/c/Users/$(logname)/Documents/Cybersecurity-Bootcamp/Linux-Module"
MAC_DIR="/Users/$(logname)/Documents/Cybersecurity-Bootcamp/Linux-Module"

# Verify Vagrant installed properly
which vagrant > /dev/null 2>&1
if [[ "$?" -ne 0 ]]; then
  echo "Vagrant not installed! Please ensure Vagrant and VirtualBox are installed before running $0!"
  exit 1
fi

echo "Vagrant version is '$(vagrant --version)'"

LINUX_DIR="/home/$(logname)/Documents/Cybersecurity-Bootcamp/Linux-Module"

# Replace LINUX_DIR with OS-specific home DIR using POSIX envvar $OSTYPE
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "Detected Linux host!"
        os=linux
elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "Detected Mac host!"
        LINUX_DIR=$MAC_DIR
        os=mac
elif [[ "$OSTYPE" == "cygwin" ]]; then
        # POSIX compatibility layer and Linux environment emulation for Windows
        echo "Detected Windows host!"
        LINUX_DIR=$WIN_DIR
        os=win
elif [[ "$OSTYPE" == "msys" ]]; then
        # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
        echo "Detected Windows host!"
        LINUX_DIR=$WIN_DIR
        os=win
else
        echo 'Failed to detect a valid host operating system!'
        exit 1
fi

# Runs commands as user in UNIX when script is run as root, null if Windows
## This should take care of non-root Vagrant commands and file/dir ownership
switch="sudo -u $(logname)"
if [[ "$os" = "win" ]]; then
  switch=""
fi

function createVagrant() {
  # Create a dedicated folder for the VM
  script_dir="$(pwd)"
  $switch mkdir -p "$LINUX_DIR"
  if [[ -f "$script_dir"/Vagrantfile ]]; then
      $switch cp "$script_dir"/Vagrantfile "$LINUX_DIR"
  else
      echo "Vagrantfile not present. Please add the Vagrantfile to the same directory you ran $0 from!."
	  exit 1
  fi
  installVagrantCommand
  startVagrant "$LINUX_DIR"
}

function installVagrantCommand() {
  # "Install" as System Command
  echo "Installing $0 as vagrant-linux CLI command..."
  SCRIPT_PATH="$(dirname $0)/$0"
  if [[ "$os" != "win" && "$EUID" -ne 0 ]]; then
    echo "Error installing 'vagrant-linux' CLI command. Please re-run with sudo!" >&2
    exit 1
  elif [[ "$os" != "win" && "$EUID" -eq 0 ]]; then
    cp "$SCRIPT_PATH" /usr/local/bin/vagrant-linux
    chmod +x /usr/local/bin/vagrant-linux
    chown $(logname): /usr/local/bin/vagrant-linux
    chown -R $(logname): "$LINUX_DIR"
    echo "Command installed! Run 'vagrant-linux --help' for a list of commands."
  fi
}

function suspendVagrant() {
  if [[ "$#" -eq 0 ]]; then
    echo 'Please provide the directory with the Vagrantfile you wish to start.' 2>&1
    exit 1
  fi
  cd "$1" || "$LINUX_DIR"
  echo "Halting VM..."
  $switch vagrant suspend
  echo "Machine halted!"
}

function resetVagrant() {
  if [[ "$#" -eq 0 ]]; then
    echo 'Please provide the directory with the Vagrantfile you wish to start.' 2>&1
    exit 1
  fi
  cd "$1" || "$LINUX_DIR"
  $switch vagrant destroy --force && $switch vagrant up
}

function startVagrant() {
  if [[ "$#" -eq 0 ]]; then
    echo 'Please provide the directory with the Vagrantfile you wish to start.' 2>&1
    exit 1
  fi
  # Launch VM
  cd "$1" || "$LINUX_DIR"
  echo "Bringing up machine..."
  $switch vagrant up
  # Verify that the machine is up
  $switch vagrant status
  # Remind user to open VirtualBox GUI to see the machine there, as well
  cat <<EOF >&1
Next, open up Virtual Box to see this VM running there, as well.
On Windows, press the Windows Key; type 'VirtualBox'; and hit ENTER.
On Mac, press Cmd + Space; type 'VirtualBox' and hit ENTER.
And that's it — enjoy!
EOF
}

function resumeVagrant() {
  if [[ "$#" -eq 0 ]]; then
    echo 'Please provide the directory with the Vagrantfile you wish to start.' 2>&1
    exit 1
  fi
  # Launch VM
  cd "$1" || "$LINUX_DIR"
  echo "Bringing up machine..."
  $switch vagrant resume || $switch vagrant up
  # Verify that the machine is up
  $switch vagrant status
  # Remind user to open VirtualBox GUI to see the machine there, as well
  cat <<EOF >&1
Next, open up Virtual Box to see this VM running there, as well.
On Windows, press the Windows Key; type 'VirtualBox'; and hit ENTER.
On Mac, press Cmd + Space; type 'VirtualBox' and hit ENTER.
And that's it — enjoy!
EOF
}

function updateBox() {
  if [[ $# -eq 0 ]]; then
    echo 'Please provide the directory with the Vagrantfile you wish to start.' 2>&1
    exit 1
  fi
  cd "$1" || "$LINUX_DIR"
  echo "Upgrading machine..."
  $switch vagrant box update
  echo "Box updated!"
  echo "Destroying old environment..."
  $switch vagrant destroy --force
  echo "Old environment removed!"
  echo "Pruning old versions"
  $switch vagrant box prune
  echo "Old versions removed!"
  echo "You can now run $0 --start to bring up the new environment!"
}

while test "$#" -gt 0; do
  case "$1" in
    -c|--create)
      createVagrant "$LINUX_DIR"
      shift
    ;;
    -i|--install)
      installVagrantCommand
      shift
    ;;
    --suspend)
      suspendVagrant "$LINUX_DIR"
      shift
    ;;
    --resume)
      resumeVagrant "$LINUX_DIR"
      shift
    ;;
    -r|--reset)
      resetVagrant "$LINUX_DIR"
      shift
    ;;
    -s|--start)
      startVagrant "$LINUX_DIR"
      shift
    ;;
    -u|--update)
      updateBox "$LINUX_DIR"
      shift
    ;;
    --help)
      echo -e 'Specify one of the following:\n  -c/--create\tInstall Vagrant VM\n  -i/--install\tInstall vagrant-linux CLI command\n  -r/--reset\tReset Vagrant VM\n  -s/--start\tStart VM\n  -u/--update\tDownload updated version of VM\n  --help\tPrint this message\n  --suspend\tStop machine and save exact state\n  -resume\tRestart machine after `vagrant-linux suspend`'
      break
    ;;
    *)
      echo -e 'Specify one of the following:\n  -c/--create\tInstall Vagrant VM\n  -i/--install\tInstall vagrant-linux CLI command\n  -r/--recreate\tReload Vagrant VM\n  -s/--start\tStart VM\n  -u/--update\tDownload updated version of VM\n  --help\tPrint this message\n  --suspend\tStop machine and save exact state\n  -resume\tRestart machine after `vagrant-linux suspend`'
      break
    ;;
  esac
done

echo -e "If you ran $0 --create, you'll be able to find your bootcamp's Vagrantfile in: \n$LINUX_DIR\n"