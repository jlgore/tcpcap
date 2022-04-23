FROM golang:alpine3.15
RUN mkdir /app
RUN apk add --no-cache build-base libpcap-dev iptables bash
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN go test
RUN go build -o tcpcap
CMD /app/tcpcap
