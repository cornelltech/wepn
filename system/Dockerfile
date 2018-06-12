
FROM alpine:latest
#---------------------------OPENVPN------------------------------
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    apk add --update tcpdump sudo openvpn iptables bash easy-rsa google-authenticator && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*
RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump
EXPOSE 1500/udp
COPY ./openvpn/conf /etc/openvpn/
VOLUME ["/etc/openvpn"]

#---------------------------MONITOR------------------------------
WORKDIR /usr/src/monitor
RUN apk --update --no-cache add musl-dev python3 python3-dev gcc tshark linux-headers libxml2-dev libxslt-dev
#RUn apt-get update
#RUN apt-get install tshark -y
RUN pip3 install pyshark requests
COPY ./monitor/main.py .

#---------------------------NGINX--------------------------------
RUN apk add --update nginx
COPY ./nginx/conf/nginx.conf /etc/nginx/nginx.conf

#---------------------------BIND---------------------------------
RUN apk --update upgrade && \
    apk add --update bind && \
    rm -rf /var/cache/apk/*
RUN mv /usr/sbin/named /usr/bin/named
COPY ./bind/conf/ /etc/bind/



COPY ./bind/bin /usr/local/bin
COPY ./monitor/bin /usr/local/bin
COPY ./nginx/bin /usr/local/bin
COPY ./openvpn/bin /usr/local/bin
COPY system_run /usr/local/bin
RUN chmod a+x /usr/local/bin/*


CMD ["system_run"]
