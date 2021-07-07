# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "linux" do |linux| # Name the machine
    linux.vm.box = "cybersecurity/desktop-base-vm" # Basic desktop machine
    linux.ssh.insert_key = false # Set to false because we would use Ansible for this
    linux.vm.synced_folder ".", "/vagrant"

    # Forwarded Port is used to test xRDP
    linux.vm.network "forwarded_port", guest: 3389, host: 3389
    linux.vm.network "private_network", type: "dhcp" # Give the machine internet access

    linux.vm.provider "hyperv" do |hv| # Specify Hyper V VM
      hv.memory = 4096
      hv.cpus = 2
    end

#    linux.vm.provider "virtualbox" do |vb| # Specify Virtual Box for VM (only runs if hyper v is not present)
#      vb.gui = true
#      vb.memory = 4096
#      vb.cpus = 2
#    end
  end

  config.vm.provision "ansible_local" do |ansible| # configure 'ansible' provisioning (as opposed to a shell script)
    ansible.verbose = "v" # Turn verbose mode on so you can see the Ansible plays running
    ansible.playbook = "provisioners/main.yml" # path to Ansible role main.yml

    # Required for GitHub Role
    ansible.extra_vars = {
      GITHUB_USERNAME: ENV["GITHUB_USERNAME"],
      GITHUB_ACCESS_TOKEN: ENV["GITHUB_ACCESS_TOKEN"]
    }
  end

end
