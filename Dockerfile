# EnactTrust QuickStart
#
# Register at https://a3s.enacttrust.com for your unique EnactTrust User ID
#

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y build-essential coreutils bsdmainutils automake libtool libcurl4-openssl-dev libssl-dev git

# wolfSSL
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssl.git && \
    cd wolfssl && ./autogen.sh && \
    ./configure --enable-wolftpm --enable-opensslextra --enable-keygen && \
    make && make install

# wolfTPM
RUN git clone --depth 1 --branch v2.5.0 https://github.com/wolfSSL/wolfTPM.git && \
    cd wolfTPM && ./autogen.sh && \
    ./configure --enable-swtpm --disable-examples && \
    make && make install

# swTPM
RUN git clone --depth 1 https://github.com/kgoldman/ibmswtpm2.git && \
    cd ibmswtpm2/src && make && cp tpm_server /usr/local/bin

# Enact agent
RUN git clone --depth 1 https://github.com/EnactTrust/enact.git && \
    cd enact && make && cp enact /usr/local/bin

RUN ldconfig
