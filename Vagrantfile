Vagrant.configure("2") do |config|
    config.vm.provider :vmware_free
    config.vm.box = "http://files.vagrantup.com/precise64_vmware.box"
    config.vm.provision :shell, path: "bootstrap.sh"
    config.vm.network "private_network", ip: "192.168.4.2"
end
