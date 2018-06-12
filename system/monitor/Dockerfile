FROM alpine:latest

WORKDIR /usr/src/monitor


RUN apk --update --no-cache add musl-dev python3 python3-dev gcc tshark linux-headers libxml2-dev libxslt-dev
#RUn apt-get update
#RUN apt-get install tshark -y
RUN pip3 install pyshark requests

COPY . .

CMD ["python3","./bin/main.py"]
