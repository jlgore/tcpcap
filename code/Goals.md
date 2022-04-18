# Project Goals

- [x] Capture PCAP from interface and log new TCP connections in specified format.
- [] Makefile to build Docker image.
- [] Tests for functions.
- [] Track connections for each IP for the last 60 seconds, if more than 3 connections happens within the minute log as a port scan.
- [] Add prometheus metric for new connections.


Next Steps: 

Connections are being sent to the struct but I can't print the count of connections. 

Log Connection Counts.
Add 60s rolling timer for "new connections"
    + means re-setting timer every time there's a new connection for another 60s
Watch for c.Count greater than 3 and block on host.
