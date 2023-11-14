FROM circleci/android:api-25-node8-alpha

# from https://stackoverflow.com/a/49585503 fixes "NO_PUBKEY
# B53DC80D13EDEF05" issue
RUN curl -s  -f https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add - 2>/dev/null

# debian stretch is out of support, so update URLs
# from https://stackoverflow.com/a/76095392
# Update stretch repositories
RUN sudo sed -i -e 's/deb.debian.org/archive.debian.org/g' \
           -e 's|security.debian.org|archive.debian.org/|g' \
           -e '/stretch-updates/d' /etc/apt/sources.list

RUN sudo apt-get update && \
    sudo apt-get install -y curl netcat android-sdk-build-tools

RUN sudo addgroup --gid 10001 app && \
    sudo adduser --gid 10001 --uid 10001 \
    --home /app --shell /sbin/nologin \
    --disabled-password app

ADD . /app

USER app
WORKDIR /app
CMD /bin/bash -c '/app/sign_test_apk.sh edge 8080 && /app/sign_test_xpi.sh edge 8080 && /app/verify_apk.sh /tmp/signed.apk'
