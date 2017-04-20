FROM debian:8

ENV http_proxy http://proxy.lbs.alcatel-lucent.com:8000
ENV https_proxy $http_proxy

RUN apt-get update && apt-get install -y \
    libssl1.0.0 \
    libncurses5 \
    libldap-2.4-2 \
    libsasl2-2 

ENV root_dir /home/test/tgen-local

WORKDIR ${root_dir}

COPY build .

WORKDIR mds_tests/Common/Tgen/fake_lib

# libraries don't have the same name in libssl1.0.0 and libssl-dev

RUN rm *

RUN ln -s $(find /usr/lib -iname "libssl*so*") libssl.so.6
RUN ln -s $(find /usr/lib -iname "libcrypto*so*") libcrypto.so.6


ENV LD_LIBRARY_PATH $root_dir/hss_freeradius/x86_64/lib:$root_dir/mds_tests/uma/Common/WpaSupplicant/x86_64:$root_dir/mds_tests/Common/Tgen/fake_lib

WORKDIR ${root_dir}/mds_tests/Common/Tgen/Bin64

