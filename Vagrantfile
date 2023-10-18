# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/36-cloud-base"
  config.vm.network "public_network", bridge: "wlo1 bridge0"
  config.vm.synced_folder ".", "/vagrant", type: "rsync",
    rsync__exclude: ["utils/", "Vagrantfile"]
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end
  config.vm.provision "shell", path: "utils/spammer_script.sh"
end
