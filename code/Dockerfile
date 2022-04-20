FROM golang:alpine3.15
RUN mkdir /app
RUN apk add --no-cache build-base libpcap-dev
ADD . /app
WORKDIR /app
RUN go build -o /app/tcpcap
CMD ["/app/tcpcap"]
