FROM ubuntu:noble

COPY . /test
COPY source /source

ARG NGINX_VERSION="1.28.0"
ARG GEOIPUPDATE_ACCOUNT_ID
ARG GEOIPUPDATE_EDITION_IDS="GeoLite2-Country GeoLite2-City"
ARG GEOIPUPDATE_LICENSE_KEY_FILE="/build/source/lk.txt"

# build nginx and geoip2 module
WORKDIR /build
RUN apt-get update && apt-get install -y libterm-readline-gnu-perl python3-launchpadlib software-properties-common \
    && add-apt-repository -y ppa:maxmind/ppa && apt-get update \
    && apt-get install -y build-essential curl libmaxminddb0 libmaxminddb-dev libpcre2-dev mmdb-bin zlib1g-dev \
    && curl -sS -4 http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar -xvzf - \
    && cd nginx-${NGINX_VERSION} \
    && cp -v ./conf/fastcgi_params /test/ \
    && ./configure --with-compat --add-dynamic-module=/source \
    && make build modules install

# download maxmind geoip databases
RUN --mount=type=secret,id=GEOIPUPDATE_LICENSE_KEY,target=$GEOIPUPDATE_LICENSE_KEY_FILE \
    apt-get install -y fcgiwrap geoipupdate recode \
    && rm -v /etc/GeoIP.conf \
    && geoipupdate -v -d /usr/share/GeoIP

# entrypoint runs fcgiwrapper and nginx
ENTRYPOINT /test/entrypoint
