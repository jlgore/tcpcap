nice -n 5 bash -c "for IP in \$(cat textfile.txt); do ipset add <setname> \$IP -exist timeout <seconds>; done"
