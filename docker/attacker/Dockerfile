# Attacker container for the isolated Netra lab.
# Standard network testing tools, used only against the victim container on the
# internal lab network (which has no route to the internet or the host LAN).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       nmap hping3 hydra slowhttptest curl iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /attacks
CMD ["sleep", "infinity"]
