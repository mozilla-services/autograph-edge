FROM circleci/android:api-25-node8-alpha

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
