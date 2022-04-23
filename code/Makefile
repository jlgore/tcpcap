.DEFAULT_GOAL := all
BIN_FILE=tcpcap

#vars
INTERFACE_NAME=eth0

.PHONY: help build push all

help:
	    @echo "Makefile arguments:"
	    @echo "INTERFACE_NAME=eth0"
	    @echo "Makefile commands:"
	    @echo "build"
	    @echo "run"
	    @echo "all"


# nukes rules for the INPUT chain for testing (need to unblock myself)
iptables:
	@sudo iptables -F INPUT
build:
	@docker build --network=host -t ${BIN_FILE} .
run:
	@docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW -e INTERFACE_NAME=${INTERFACE_NAME} ${BIN_FILE}
 
all: iptables build run