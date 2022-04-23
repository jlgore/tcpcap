
* Required dependencies on a Ubuntu 20.04 host machine:
    * `make`
    * `gcc`
    * `libpcap-dev`
* Install Docker (or use the `vmbootstrap.sh` script run as `root`)
* Clone the repo `git clone https://github.com/jlgore/tcpcap.git`
* Build the docker container `sudo docker build .  --network=host`
* Run the docker container with elevated privledges `sudo docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW <container name>`


