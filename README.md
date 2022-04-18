# golang tcpcap

A golang program to track TCP connections via [gopacket](https://github.com/google/gopacket) and companion libraries to log and alert on:

* New TCP Connections
* Port Scans
* Blocked IP addresses

# To Do

- [] capture packets and log new connections.


# Dependencies

This application was build on an Ubuntu 20.04 VM. It requires `gcc` and `libpcap-dev` to be installed on the VM you use for testing. Hopefully, a provisioning script supplied will assist you in getting everything working smoothly.

