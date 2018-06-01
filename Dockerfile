FROM golang:1.10
MAINTAINER Mozilla
EXPOSE 8080

RUN addgroup --gid 10001 app && \

    adduser --gid 10001 --uid 10001 \
    --home /app --shell /sbin/nologin \
    --disabled-password app && \

    apt update && \
    apt -y upgrade && \
    apt-get clean

ADD . $GOPATH/src/go.mozilla.org/autograph-edge
ADD autograph-edge.yaml /app
ADD version.json /app

RUN go get -u golang.org/x/vgo && \
    cd $GOPATH/src/go.mozilla.org/autograph-edge && \
    make install

USER app
WORKDIR /app
CMD $GOPATH/bin/autograph-edge
