ARG GO_VERSION=1.22

#------------------------------------------------------------------------------
# Base Debian Image
#------------------------------------------------------------------------------
FROM debian:bookworm AS base
ARG GO_VERSION

ENV DEBIAN_FRONTEND='noninteractive' \
    PATH="${PATH}:/usr/lib/go-${GO_VERSION}/bin:/go/bin" \
    GOPATH='/go'

## Enable bookworm-backports
RUN echo "deb http://deb.debian.org/debian/ bookworm-backports main" > /etc/apt/sources.list.d/bookworm-backports.list
RUN echo "deb-src http://deb.debian.org/debian/ bookworm-backports main" >> /etc/apt/sources.list.d/bookworm-backports.list

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install --no-install-recommends \
        clang \
        gcc \
        libltdl-dev \
        git \
        golang-${GO_VERSION} \
        curl \
        ca-certificates && \
    # Cleanup inline with installation to avoid this layer being bloated with
    # deb packages and other cached data.
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

#------------------------------------------------------------------------------
# Build Stage
#------------------------------------------------------------------------------
FROM base AS builder
ARG VERSION_COMMIT_HASH
ARG VERSION_SOURCE_URL
ARG VERSION_BUILD_URL
ARG VERSION_TAG_NAME
ENV GO111MODULE=on
ENV CGO_ENABLED=1

ADD . /app/src

RUN cd /app/src && go generate
RUN cd /app/src && go install .

#------------------------------------------------------------------------------
# Deployment Stage
#------------------------------------------------------------------------------
FROM base
EXPOSE 8080

# Copy compiled appliation from the builder.
RUN mkdir /app
ADD autograph-edge.yaml /app
COPY --from=builder /app/src/version.json /app
COPY --from=builder /go/bin/autograph-edge /usr/local/bin/autograph-edge

# Setup the worker and entrypoint.
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
WORKDIR /app
CMD /usr/local/bin/autograph-edge
