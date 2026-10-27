FROM ubuntu:24.04

LABEL org.opencontainers.image.title="anzen" \
      org.opencontainers.image.description="Linux Security Audit Tool"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        coreutils \
        findutils \
        grep \
        procps \
        net-tools \
        iproute2 \
        iproute2-tc \
        openssl \
        curl \
        file \
        python3 \
        ca-certificates \
        libpam-modules \
        passwd \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /anzen
COPY . /anzen/

RUN chmod +x /anzen/anzen.sh /anzen/install.sh && \
    mkdir -p /anzen/reports

VOLUME ["/anzen/reports"]

# anzen audits the system it runs on, so inside a container it audits the
# container. Use the image as a portable runner for remote/fleet audits:
#   docker build -t anzen .
#   docker run --rm -v ~/.ssh:/root/.ssh:ro -v "$PWD/reports":/anzen/reports \
#     anzen --remote=root@host1,root@host2 --html

ENTRYPOINT ["bash", "/anzen/anzen.sh"]
CMD ["--help"]
