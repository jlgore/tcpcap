# test stage
FROM golang:alpine AS test-env
RUN apk --no-cache add build-base gcc libpcap-dev iptables
ADD . /src
RUN cd /src && go test

# build stage
FROM golang:alpine AS build-env
RUN apk --no-cache add build-base gcc libpcap-dev iptables
ADD . /src
RUN cd /src && go build -o tcpcap

# run stage
FROM alpine
WORKDIR /app
COPY --from=build-env /src/tcpcap /app/tcpcap
CMD /app/tcpcap

