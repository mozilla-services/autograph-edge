FROM golang:1.13.1-buster
EXPOSE 8080

RUN addgroup --gid 10001 app && \
    adduser --gid 10001 --uid 10001 \
    --home /app --shell /sbin/nologin \
    --disabled-password app

RUN apt update && \
    apt -y upgrade && \
    apt -y install clang libltdl-dev && \
    apt-get clean

ADD . $GOPATH/src/go.mozilla.org/autograph-edge
ADD autograph-edge.yaml /app
ADD version.json /app

RUN go get -u golang.org/x/vgo && \
    cd $GOPATH/src/go.mozilla.org/autograph-edge && \
    make install

RUN apt-get -y remove clang && \
    apt-get clean && \
    apt-get -y autoremove

USER app
WORKDIR /app
CMD $GOPATH/bin/autograph-edge
