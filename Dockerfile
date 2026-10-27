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

# Run with --privileged and mount the host root to audit a real host:
#   docker run --rm --privileged \
#     -v /:/host:ro \
#     -v $(pwd)/reports:/anzen/reports \
#     anzen --html
#
# Or audit a remote host:
#   docker run --rm -v ~/.ssh:/root/.ssh:ro \
#     -v $(pwd)/reports:/anzen/reports \
#     anzen --remote=user@host --html

ENTRYPOINT ["bash", "/anzen/anzen.sh"]
CMD ["--help"]
