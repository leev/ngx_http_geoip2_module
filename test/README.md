# ngx_http_geoip2_module Test Container

This directory contains resources to build a Docker container to test ngx_http_geoip2_module.

First set GEOIPUPDATE_ACCOUNT_ID and GEOIPUPDATE_LICENSE_KEY environment variables for authentication with MaxMind to download databases.

For example run a command like the following:
```
export GEOIPUPDATE_ACCOUNT_ID=12345 GEOIPUPDATE_LICENSE_KEY=$(pass show '/auth/maxmind-license-key')
```

Then run `make` or `make container run` in this directory to build and start the container.

The container exposes Nginx on local port 8888. Make requests in the form http://localhost:8888/$IP to test out the geoip2 module. The IP provided as part of the path is passed to the geoip2 module. The default endpoint prints its environment including variables prefixed with GEOIP2 set by the geoip2 module.

For example:

```
$> curl -fsS localhost:8888/$(curl -sS ident.me) | grep GEOIP2
GEOIP2_CITY_EPOCH=1745917200
GEOIP2_CITY_NAME=Haverhill
GEOIP2_COUNTRY_CODE=US
GEOIP2_COUNTRY_EPOCH=1745917530
GEOIP2_COUNTRY_NAME=United States
```
