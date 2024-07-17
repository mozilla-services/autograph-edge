ARG GO_VERSION=1.22

#------------------------------------------------------------------------------
# Base Debian Image
#------------------------------------------------------------------------------
FROM debian:bookworm as base
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
FROM base as builder
ENV GO111MODULE on
ENV CGO_ENABLED 1

ADD . /app/src/autograph

RUN cd /app/src/autograph && go install .

#------------------------------------------------------------------------------
# Deployment Stage
#------------------------------------------------------------------------------
FROM base
EXPOSE 8080

# fetch the RDS CA bundles
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
RUN curl -o /usr/local/share/old-rds-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem && \
      curl -o /usr/local/share/new-rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
      cat /usr/local/share/old-rds-ca-bundle.pem /usr/local/share/new-rds-ca-bundle.pem > /usr/local/share/rds-combined-ca-bundle.pem

# Copy compiled appliation from the builder.
ADD . /app/src/autograph
ADD autograph-edge.yaml /app
ADD version.json /app
COPY --from=builder /go/bin/autograph-edge /go/bin/autograph-edge

# Setup the worker and entrypoint.
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
WORKDIR /app
CMD /go/bin/autograph-edge
