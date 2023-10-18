 #create Vagrantfile
    NET_ADAPTER=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
    echo 'Create Vagrantfile with '$NET_ADAPTER' as network adapter.'

    echo '# -*- mode: ruby -*-' > Vagrantfile
    echo '# vi: set ft=ruby :' >> Vagrantfile
    echo '' >> Vagrantfile
    echo 'Vagrant.configure("2") do |config|' >> Vagrantfile
    echo '  config.vm.box = "fedora/36-cloud-base"' >> Vagrantfile
    echo '  config.vm.network "public_network", bridge: "'$NET_ADAPTER'"' >> Vagrantfile
    echo '  config.vm.synced_folder ".", "/vagrant", type: "rsync",' >> Vagrantfile
    echo '    rsync__exclude: ["utils/", "Vagrantfile"]' >> Vagrantfile
    echo '  config.vm.provider "virtualbox" do |v|' >> Vagrantfile
    echo '    v.memory = 2048' >> Vagrantfile
    echo '    v.cpus = 2' >> Vagrantfile
    echo '  end' >> Vagrantfile
    echo '  config.vm.provision "shell", path: "utils/spammer_script.sh"' >> Vagrantfile
    echo 'end' >> Vagrantfile

    #install spammerVM
    sudo -u $(logname) vagrant up --provision