.DEFAULT_GOAL := all
BIN_FILE=tcpcap

.PHONY: help build push all

help:
	    @echo "Makefile arguments:"
	    @echo "lol"
	    @echo "uwish"
	    @echo "Makefile commands:"
	    @echo "build"
	    @echo "run"
	    @echo "all"

build:
	@docker build --network=host -t ${BIN_FILE} .
run:
	@docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW ${BIN_FILE}

all: build run