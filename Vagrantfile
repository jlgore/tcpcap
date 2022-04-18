Vagrant.configure("2") do |config|
    config.vm.define "pcap" do |pcap|
      pcap.vm.box = "ubuntu/focal64"
      pcap.vm.hostname = 'pcappy'
      pcap.vm.box_url = "https://app.vagrantup.com/ubuntu/boxes/focal64"
  
      pcap.vm.network :private_network, ip: "192.168.56.101"
  
      pcap.vm.provider :virtualbox do |v|
        v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        v.customize ["modifyvm", :id, "--memory", 2048]
        v.customize ["modifyvm", :id, "--name", "pcap"]
      end

      pcap.vm.provision "shell",
        path: "~/tcpcap/scripts/vmbootstrap.sh"

    end
  
    config.vm.define "kali" do |kali|
      kali.vm.box = "kalilinux/rolling"
      kali.vm.hostname = 'kali'
      kali.vm.box_url = "https://app.vagrantup.com/kalilinux/boxes/rolling"
  
      kali.vm.network :private_network, ip: "192.168.56.102"
  
      kali.vm.provider :virtualbox do |v|
        v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        v.customize ["modifyvm", :id, "--memory", 512]
        v.customize ["modifyvm", :id, "--name", "kali"]
      end
    end
  end
