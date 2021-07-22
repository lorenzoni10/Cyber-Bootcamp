# -*- mode: ruby -*-
# vi: set ft=ruby :

## This Vagrantfile will set up the Unit 6 Homework Environment
# To start these machines, use the command: vagrant up
# To stop these machines, use the command: vagrant halt
# To remove these machines, use the command: vagrant destroy, and then confirm removal

Vagrant.configure("2") do |config|
  config.vm.define "scavenger" do |scavenger|
    scavenger.vm.box = "cybersecurity/linux-scavenger"
    scavenger.vm.box_version = "1.0.7"
    scavenger.vm.ignore_box_vagrantfile = true
    scavenger.ssh.insert_key = false
    #scavenger.vm.hostname = "Linux-Scavenger"
    scavenger.vm.network "private_network", ip: "192.168.6.105"
    scavenger.vm.synced_folder ".", "/vagrant", disabled: true
    #Disabling VB Guest Additions auto updates for this headless VM
    if Vagrant.has_plugin?("vagrant-vbguest")
        config.vbguest.auto_update = false
    end
    scavenger.vm.provider "virtualbox" do |vb| # specify vbox provisioning
      vb.memory = 1024
      vb.cpus = 1
      vb.name = "Target Machine"
      vb.gui = false
      vb.customize ['modifyvm', :id, '--clipboard', 'bidirectional']
    end
  end
  config.vm.define "ubuntu" do |ubuntu|
    ubuntu.vm.box = "cybersecurity/UbuntuVM"
#    ubuntu.vm.ignore_box_vagrantfile = true
#    ubuntu.ssh.insert_key = false
    #ubuntu.vm.hostname = "Ubuntu"
    ubuntu.vm.network "private_network", ip: "192.168.6.104"
    ubuntu.vm.synced_folder ".", "/vagrant", disabled: true
    ubuntu.vm.provider "virtualbox" do |vb| # specify vbox provisioning
      # Uncomment ONE the lines below to control how much RAM Vagrant gives the VM
      # We recommend starting with 4096 (4Gb), and moving down if necessary
      # vb.memory = "1024" # 1Gb
      # vb.memory = "2048" # 2Gb
      # vb.memory = "4096" # 4Gb
      vb.gui = true
      vb.name = "Attacker Machine"
      vb.customize ['modifyvm', :id, '--clipboard', 'bidirectional']
    end
  end
end
