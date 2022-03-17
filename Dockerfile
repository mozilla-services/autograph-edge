FROM golang:1.18.0-buster AS build
ENV GO111MODULE on

RUN apt update && \
    apt -y upgrade && \
    apt -y install clang libltdl-dev && \
    apt-get clean

ADD . $GOPATH/src/github.com/mozilla-services/autograph-edge

RUN cd $GOPATH/src/github.com/mozilla-services/autograph-edge && \
    make install

RUN apt-get -y remove clang && \
    apt-get clean && \
    apt-get -y autoremove

FROM debian:buster-slim
EXPOSE 8080

RUN apt update && \
    apt -y upgrade && \
    apt -y install libltdl-dev ca-certificates && \
    apt-get clean

COPY --from=build /go/bin/autograph-edge /usr/local/bin

RUN addgroup --gid 10001 app && \
    adduser --gid 10001 --uid 10001 \
    --home /app --shell /sbin/nologin \
    --disabled-password app

ADD autograph-edge.yaml /app
ADD version.json /app

USER app
WORKDIR /app
CMD /usr/local/bin/autograph-edge
