FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
	build-essential \
	git \
    wget \
	curl \
    libssl-dev \
    libpcre3-dev \
	ca-certificates \
	--no-install-recommends

WORKDIR /src
RUN git clone https://gitlab.com/akihe/radamsa \
	&& git clone https://github.com/aoh/blab \
	&& git clone https://github.com/denandz/fuzzotron
WORKDIR /src/radamsa
RUN make \
	&& make install
WORKDIR /src/blab
RUN make \
	&& make install
WORKDIR /src/fuzzotron
RUN make
