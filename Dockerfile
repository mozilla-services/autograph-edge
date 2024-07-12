FROM golang:1.17.3-buster AS build
ENV GO111MODULE on

RUN apt update && \
    apt -y upgrade && \
    apt-get clean

ADD . $GOPATH/src/github.com/mozilla-services/autograph-edge

RUN cd $GOPATH/src/github.com/mozilla-services/autograph-edge && \
    make install

FROM debian:buster-slim
EXPOSE 8080

RUN apt update && \
    apt -y upgrade && \
    apt -y install ca-certificates && \
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
