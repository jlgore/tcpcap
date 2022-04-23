# golang tcpcap

A golang program to track TCP connections via [gopacket](https://github.com/google/gopacket) and companion libraries to log and grab prometheus metrics on:

* New TCP SYN Connections
* Port Scan Attempts
* Blocked IP addresses

# To Do

- [x] capture packets and log new connections.
- [x] increment prometheus counters for total number of connections tracked and number of blocked IPs.
- [] Why does it sometime detect outgoing traffic as incoming?
- [] block IPs in iptables. Pray it blocks on the host.
    * Test blocks crashing application -- might be good now
    * Understand why some connections SHOULD be blocked and aren't
    * Test optional TARPIT
    * Test if iptables on host continues to block after docker container is no longer running.
- [x] Dockerize applications.
- [X] Build, test, and run application in docker using `Makefile`.
- [] Write tests for other functions in `main`


# Dependencies

This application was build on an Ubuntu 20.04 VM. It requires `gcc`, `make`, `libpcap-dev` and Docker Engine to be installed on the VM you use for testing. Hopefully, a provisioning script supplied will assist you in getting everything working smoothly.

# Why you do what you did?

I used golang because the language is flexible enough where I can read some examples and figure out how to hack something together to prove the concept and refine it as we move along. There's downsides to moving quickly but I try and move fast and break things early and often upfront. My favorite seratonin producing moment is "oh yay! new error message!" If I find the hardest problems early on the problems that arise later shouldn't be too bad. 

I wanted to store each address that connects in a struct with a count of how many times it's connected and an array of timestamps of each connection time. My hope was to find a way to store a dynamic set of timers using channels and spinning up a new timer for each IP present in the struct but I wasn't able to make that work how I wanted.

To block (which was way simpler than I thought), I just used an iptables library and passed `net=host`. I didn't think it would work but it did and I didn't need anything more complex. 

