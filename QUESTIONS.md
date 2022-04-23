## LEVEL 1 Questions

### How would you prove the code is correct?

The only way to prove the code is accurate is to run tests with a known/crafted pcap against both the project code and old school bash analysis with tools like `tcpdump` or `tshark` with some piping to other tools to verify unique connection counts. 

If the crafted packets send a known number of connections to a host we should be able to check the output of both tests against each other for accuracy. 

The other "out of band" way of tracking this would be to aggregate netflow logs from your VPC or Home Lab router/switch and run analysis outside of the host in question. The benefit here is rootkits might be able to obfuscate certain behavior from the applications running on the host but networking gear would have to be compromised to a similar extent to hide all attacker tracks.

### How would you make this solution better?

I have been using golang for a few years, but I have really only  programming in it "full time" for about nine months. It's been a beautiful learning curve, but I know I still have a lot to learn. I think one thing I would do is have a better way of tracking connection state. Initially, I was trying to have channels keep track of repeat connections on a rolling timer. This...does not scale well. I want to be cognizant of resources on the host and not allow my connection tracking program to consume all of the resources that might be reserved for other applications. Technically an attacker could spam the server with connections and we could get overwhelmed with this strategy. Right now I am just looking at the timestamps for each IP address in an Array and seeing if these connections fall within a window of one minute, which is really not elegant.


### Is it possible for this program to miss a connection?

100% possible and very probable. I wanted to do some chaos engineering for this because I didn't want it to crash and embarass myself. The things I was aiming for were like:

* Can I drop invalid packets to reduce the attack surface of the monitoring application?
* Are there particular patterns of connection that would overwhelm the application itself?
* If the host interface is flooded with a high quanity of packets will `gopacket` be able to keep up? I run into this problem with IDS applications from time to time as well.

Very little of this testing came to fruition due to time constraints.


### If you weren't following these requirements, how would you solve the problem of logging every new connection?

I'm still *learning* everyday, and that includes Prometheus. I think pushing custom metrics to a time series service might give us what we need, but I couldn't find a way to do that this week. To make this scale I would look at running this capture two ways:

* Netflow logs exported to s3, use Athena or another application that can query and aggregate the flows by top TCP SYN talkers, top TCP SYN connections on multiple ports from one host in the 60s target window, etc. Results get sent to lambas which add to a blocklist that is loaded on to hosts via automation. IPs could also be blocked at the WAF, Security Group, NACL levels as well depending on the tolerance level.

* Send host traffic to a centralized IDS cluster with IDS rules tuned to detecting these scans. Zeek scripts could detect the scan and trigger jobs to block.

Both of these solutions lose the immediacy of being on the host, which is a downside. If the requirement of low latency/no latency is needed then a direct eBPF application is probably the only way of doing it.

## LEVEL 2 Questions

### Why did you choose `make` to write the build automation?

I wanted to learn more about Make.

### Is there anything else you would test if you had more time?

### What is the most important tool, script, or technique you have for solving problems in production? Explain why this tool/script/technique is the most important.

## LEVEL 3 Questions

### If you had to deploy this program to hundreds of servers, what would be your preferred method? Why?

It depends on the architecture and the specific problems we would be looking to address, but I will break this down into:

* VMs - I would bake the application into the virtual machine image and build new AMIs when a new version is released. This has downsides and is not as agile as using something like AWS CodeDeploy to deploy new versions out to a fleet of servers. It strikes me an application of this nature is something you would deploy alongside other server hardening tools. Those tools are generally not updated as often as the revenue generating applications so it might not need the full blue/green deployment treatment.

* Bare Metal / Hypervisors - I would use something like Ansible to manage the installation and update process on this host type. The playbook can handle installation, service creation, and updating as time goes on.

## What is the hardest technical problem or outage you've had to solve in your career? Explain what made it so difficult?

For me the hardest problems I've had to overcome are because I don't have senior people to learn from and lean on. I am grateful for my friends and colleagues because we make the mistakes together. Sometimes my instincts are wrong, sometimes my instincts are correct but I wasn't looking in the right place. I've broken a lot of things, sometimes on accident...sometimes on purpose but I am always seeking the advice of those who have done it before so I can avoid the mistakes and pitfalls. I've had to learn how to look and where to look for answers, but sometimes I don't even know what I should be searching for. Sometimes all it takes is a bit of guidance from an expert to ensure success.

If you REALLY want a technical answer though: my hardest 'technical' challenges have been scale related. It can be hard to track down where the bottle neck is coming from on certain AWS services (*cough cough* Fargate). One time I was faced with certain routes of a monolith failing on agent check-in. The app never stopped responding to normal web traffic and all our monitoring tools. However, automated agents were getting 504s from the load balancer on their regular check-in intervals. This caused the app functionality to drop and caused a large spike in support tickets. After going back and forth between the development team and AWS we determined the automated check-ins were overwhelming the cluster capacity every 15 minutes. Increasing the number of containers in the service resolved the issue temporarily, but it will continue to require more and more capacity to handle agent traffic as the company grows. We recommended moving the agent check-in to an API gateway that can scale better. We also recommended staggering check-in to reduce load on the existing cluster. 