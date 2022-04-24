# golang tcpcap

A golang program to track TCP connections via [gopacket](https://github.com/google/gopacket) and companion libraries to log and expose prometheus metrics on:

* New TCP SYN Connections
* Blocked IP addresses

# To Do

- [x] capture packets and log new connections.
- [x] increment prometheus counters for total number of connections tracked and number of blocked IPs.
- [x] How to filter only incoming traffic.
- [x] block IPs in iptables. Pray it blocks on the host.
    * Test blocks crashing application -- might be good now
    * Understand why some connections SHOULD be blocked and aren't --> i understand now my code was broken
- [x] Dockerize applications.
- [X] Build, test, and run application in docker using `Makefile`.
- [] Write tests for other functions in `main` -- struggled trying to test the function where I did the bulk of the logic/work. If I had more time I would craft pcaps that had known traffic that would be blocked/not blocked. 

# How to Run

Clone the project and `cd` into the `code` directory. You can set the docker variables in the  `Makefile`. `sudo make` will build a docker container that has privledges to sniff traffic on the host. The docker container runs tests and compiles the go binary and launches it as the `CMD`. 

## Variables needed for Makefile:

`INTERFACE_NAME=your_interface_name` - used to specifiy the docker container interface for sniffing
`PUBLIC_IP=your_public_ip` - used to identify the host IP address to the golang app, sometimes I would run into a bug where outgoing traffic was being included depending on cronjobs (or in my case a remote VSCode session). One time I even blocked the host from the host!

# Dependencies

This application was built on an Ubuntu 20.04 VM. It requires `gcc`, `make`, `libpcap-dev` and Docker Engine to be installed on the VM you use for testing. Hopefully, the included provisioning script supplied (under `scripts/vmbootstrap.sh`) will assist you in getting everything working smoothly. 

### Manual Server Provisioning

* Required dependencies on a Ubuntu 20.04 host machine:
    * `make`
    * `gcc`
    * `libpcap-dev`
* Install Docker Engine (or use the `vmbootstrap.sh` script run as `root`)
* Clone the repo `git clone https://github.com/jlgore/tcpcap.git`
* `sudo make` to build and run the container.

All the code, Dockerfile, and fun stuff lives in the `code` directory.

# Why you do what you did?

I used golang because the language is flexible enough where I can read some examples and figure out how to hack something together to prove the concept and refine it as we move along. There's downsides to moving quickly but I try and move fast and break things early and often upfront. My favorite seratonin producing moment is "oh yay! new error message!" If I find the hardest problems early on the problems that arise later shouldn't be too bad. 

I wanted to store each address that connects in a struct with a count of how many times it's connected and an array of timestamps of each connection time. My hope was to find a way to store a dynamic set of timers using channels and spinning up a new timer for each IP present in the struct but I wasn't able to make that work how I wanted.

To block (which was way simpler than I thought), I just used an iptables library and passed `net=host` to the docker container. I didn't think it would work but it did and I didn't need anything more complex. 

If you block a machine and you would like to unblock, I have a command in the Makefile `make iptables` which will destroy all filter rules in the `INPUT` chain on netfilter. 