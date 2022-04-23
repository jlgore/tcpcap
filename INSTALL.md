
* Install required dependencies on the host machine:
    * `make`
    * `gcc`
    * `libpcap-dev`
* Build the docker container `sudo docker build .  --network=host`
* Run the docker container with elevated privledges `sudo docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW <container name>`

