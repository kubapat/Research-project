# container for `chestnut`
FROM ubuntu:18.04
ENV TZ=Europe/Amsterdam

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install \
    build-essential \
    git \
    python3.8 \
    python3-pip \
    python3.8-venv \
    nano \
    nginx \
    strace

WORKDIR /tool
RUN git clone -b binalyzer-fix https://github.com/felacek/Chestnut.git


WORKDIR Chestnut/Binalyzer
RUN python3 -m venv venv
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt

EXPOSE 80

CMD bash