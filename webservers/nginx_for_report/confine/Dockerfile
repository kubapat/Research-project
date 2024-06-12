# container for `confine`
FROM ubuntu:18.04

RUN apt-get update && apt-get -y install \
    build-essential \
    git \
    python3.7

RUN apt-get -y install apt-transport-https ca-certificates curl software-properties-common sysdig
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
RUN apt-get update
RUN apt-cache policy docker-ce
RUN apt-get -y install docker-ce

WORKDIR /tool
RUN git clone https://github.com/shamedgh/confine.git

WORKDIR confine

CMD bash