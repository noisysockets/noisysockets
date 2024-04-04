FROM debian:bullseye-slim

RUN apt update \
  && apt install -y bind9

RUN mkdir -p /var/named \
  && chown bind:bind /var/named

COPY named.conf /etc/bind/named.conf

COPY noisysockets.github.com.zone /var/named/noisysockets.github.com.zone
RUN chown bind:bind /var/named/noisysockets.github.com.zone

CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind"]
