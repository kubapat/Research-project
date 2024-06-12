# container for `sysfilter`
FROM ubuntu:18.04

RUN apt-get update && apt-get -y install \
    build-essential \
    libc6-dbg \
    git \
    lcov \
    libreadline-dev \
    gdb \
    lsb-release \
    nano \
    python3-parameterized \
    nginx \
    strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tool
RUN git clone --recursive https://gitlab.com/Egalito/sysfilter.git

WORKDIR sysfilter/extraction
RUN make -j8

EXPOSE 80

CMD bash