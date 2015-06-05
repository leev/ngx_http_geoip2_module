Description
===========

**ngx_http_geoip2_module** - creates variables with values from the maxmind geoip2 databases based on the client IP (supports both IPv4 and IPv6)

## Installing
First install [libmaxminddb](https://github.com/maxmind/libmaxminddb) as described in its [README.md
file](https://github.com/maxmind/libmaxminddb/blob/master/README.md#installing-from-a-tarball).

Compile nginx:
```
./configure --add-module=/path/to/ngx_http_geoip2_module
make 
make install
```

## Download Maxmind GeoLite2 Database (optional)
The free GeoLite2 databases are available from [Maxminds website](http://dev.maxmind.com/geoip/geoip2/geolite2/)

[GeoLite2 City](http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz)
[GeoLite2 Country](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz)

## Example Usage:
```
http {
    ...
    geoip2 /etc/maxmind-country.mmdb {
        $geoip2_data_country_code default=US country iso_code;
        $geoip2_data_country_name country names en;
    }

    geoip2 /etc/maxmind-city.mmdb {
        $geoip2_data_city_name default=London city names en;
    }
    ....
}
```

## Full Example

The following can go in your main nginx config or an include. The field names map to the max mind db values. Note where you see "en" that is a language code, be sure to check the database has the languages you are referencing.

```
    geoip2 /etc/maxmind-city.mmdb {
        $geoip2_data_continent_code continent code;
        $geoip2_data_country_iso_code country iso_code;
        $geoip2_data_subdivisions_name subdivisions 0 names en;
        $geoip2_data_city_name city names en;
        $geoip2_data_latitude location latitude;
        $geoip2_data_longitude location longitude;
   }

```

## Sample Fastcgi Params

Place the following in a location block where you are using fastcgi params

```
fastcgi_param GEO_CONTINENT $geoip2_data_continent_code;
fastcgi_param GEO_COUNTRY $geoip2_data_country_iso_code;
fastcgi_param GEO_REGION $geoip2_data_subdivisions_name;
fastcgi_param GEO_CITY $geoip2_data_city_name;
fastcgi_param GEO_LATITUDE $geoip2_data_latitude;
fastcgi_param GEO_LONGITUDE $geoip2_data_longitude;

```

