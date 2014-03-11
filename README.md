Description
===========

**ngx_http_geoip2_module** - creates variables with values from the maxmind geoip2 databases based on the client IP (supports both IPv4 and IPv6)

## Example Usage:
```
http {
    ...
    geoip2_mmdb        /etc/maxmind-city.mmdb;
    geoip2_data        $geoip2_data_country_code country iso_code;
    geoip2_data        $geoip2_data_country_name country names en;
    geoip2_data        $geoip2_data_city_name city names en;
    geoip2_data        $geoip2_data_geoname_id country geoname_id;
    geoip2_data        $geoip2_data_latitude location latitude;
    ....
}
```
