Description
===========

**ngx_http_geoip2_module** - creates variables with values from the maxmind geoip2 databases based on the client IP (default) or from a specific variable (supports both IPv4 and IPv6)

The module now supports nginx streams and can be used in the same way the http module can be used.

## Installing
First install [libmaxminddb](https://github.com/maxmind/libmaxminddb) as described in its [README.md
file](https://github.com/maxmind/libmaxminddb/blob/master/README.md#installing-from-a-tarball).

#### Download nginx source
```
wget http://nginx.org/download/nginx-VERSION.tar.gz
tar zxvf nginx-VERSION.tar.gz
cd nginx-VERSION
```

##### To build as a dynamic module (nginx 1.9.11+):
```
./configure --add-dynamic-module=/path/to/ngx_http_geoip2_module
make
make install
```

This will produce ```objs/ngx_http_geoip2_module.so```. It can be copied to your nginx module path manually if you wish.

Add the following line to your nginx.conf:
```
load_module modules/ngx_http_geoip2_module.so;
```

##### To build as a static module:
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
        $geoip2_data_country_code default=US source=$variable_with_ip country iso_code;
        $geoip2_data_country_name country names en;
    }

    geoip2 /etc/maxmind-city.mmdb {
        $geoip2_data_city_name default=London city names en;
    }
    ....

    fastcgi_param COUNTRY_CODE $geoip2_data_country_code;
    fastcgi_param COUNTRY_NAME $geoip2_data_country_name;
    fastcgi_param CITY_NAME    $geoip2_data_city_name;
    ....
}

stream {
    ...
    geoip2 /etc/maxmind-country.mmdb {
        $geoip2_data_country_code default=US source=$remote_addr country iso_code;
    }
    ...
}
```

To find the path of the data you want (eg: city names en), use the [mmdblookup tool](https://maxmind.github.io/libmaxminddb/mmdblookup.html) to interrogate either the Country database:

```
$ mmdblookup --file /usr/share/GeoIP/GeoIP2-Country.mmdb --ip 8.8.8.8

  {
    "continent":
      {
        "code":
          "NA" <utf8_string>
        "geoname_id":
          6255149 <uint32>
        "names":
          {
            "de":
              "Nordamerika" <utf8_string>
            "en":
              "North America" <utf8_string>
            "es":
              "Norteamérica" <utf8_string>
            "fr":
              "Amérique du Nord" <utf8_string>
            "ja":
              "北アメリカ" <utf8_string>
            "pt-BR":
              "América do Norte" <utf8_string>
            "ru":
              "Северная Америка" <utf8_string>
            "zh-CN":
              "北美洲" <utf8_string>
          }
      }
    "country":
      {
        "geoname_id":
          6252001 <uint32>
        "iso_code":
          "US" <utf8_string>
        "names":
          {
            "de":
              "USA" <utf8_string>
            "en":
              "United States" <utf8_string>
            "es":
              "Estados Unidos" <utf8_string>
            "fr":
              "États-Unis" <utf8_string>
            "ja":
              "アメリカ合衆国" <utf8_string>
            "pt-BR":
              "Estados Unidos" <utf8_string>
            "ru":
              "США" <utf8_string>
            "zh-CN":
              "美国" <utf8_string>
          }
      }
    "registered_country":
      {
        "geoname_id":
          6252001 <uint32>
        "iso_code":
          "US" <utf8_string>
        "names":
          {
            "de":
              "USA" <utf8_string>
            "en":
              "United States" <utf8_string>
            "es":
              "Estados Unidos" <utf8_string>
            "fr":
              "États-Unis" <utf8_string>
            "ja":
              "アメリカ合衆国" <utf8_string>
            "pt-BR":
              "Estados Unidos" <utf8_string>
            "ru":
              "США" <utf8_string>
            "zh-CN":
              "美国" <utf8_string>
          }
      }
  }
```
or the City one:
```
$ mmdblookup --file /usr/share/GeoIP/GeoIP2-City.mmdb --ip 139.218.70.158

  {
    "city":
      {
        "geoname_id":
          2171586 <uint32>
        "names":
          {
            "en":
              "Chipping Norton" <utf8_string>
          }
      }
    "continent":
      {
        "code":
          "OC" <utf8_string>
        "geoname_id":
          6255151 <uint32>
        "names":
          {
            "de":
              "Ozeanien" <utf8_string>
            "en":
              "Oceania" <utf8_string>
            "es":
              "Oceanía" <utf8_string>
            "fr":
              "Océanie" <utf8_string>
            "ja":
              "オセアニア" <utf8_string>
            "pt-BR":
              "Oceania" <utf8_string>
            "ru":
              "Океания" <utf8_string>
            "zh-CN":
              "大洋洲" <utf8_string>
          }
      }
    "country":
      {
        "geoname_id":
          2077456 <uint32>
        "iso_code":
          "AU" <utf8_string>
        "names":
          {
            "de":
              "Australien" <utf8_string>
            "en":
              "Australia" <utf8_string>
            "es":
              "Australia" <utf8_string>
            "fr":
              "Australie" <utf8_string>
            "ja":
              "オーストラリア" <utf8_string>
            "pt-BR":
              "Austrália" <utf8_string>
            "ru":
              "Австралия" <utf8_string>
            "zh-CN":
              "澳大利亚" <utf8_string>
          }
      }
    "location":
      {
        "accuracy_radius":
          500 <uint16>
        "latitude":
          -33.952200 <double>
        "longitude":
          150.899500 <double>
        "time_zone":
          "Australia/Sydney" <utf8_string>
      }
    "postal":
      {
        "code":
          "2170" <utf8_string>
      }
    "registered_country":
      {
        "geoname_id":
          2077456 <uint32>
        "iso_code":
          "AU" <utf8_string>
        "names":
          {
            "de":
              "Australien" <utf8_string>
            "en":
              "Australia" <utf8_string>
            "es":
              "Australia" <utf8_string>
            "fr":
              "Australie" <utf8_string>
            "ja":
              "オーストラリア" <utf8_string>
            "pt-BR":
              "Austrália" <utf8_string>
            "ru":
              "Австралия" <utf8_string>
            "zh-CN":
              "澳大利亚" <utf8_string>
          }
      }
    "subdivisions":
      [
        {
          "geoname_id":
            2155400 <uint32>
          "iso_code":
            "NSW" <utf8_string>
          "names":
            {
              "en":
                "New South Wales" <utf8_string>
              "fr":
                "Nouvelle-Galles du Sud" <utf8_string>
              "pt-BR":
                "Nova Gales do Sul" <utf8_string>
              "ru":
                "Новый Южный Уэльс" <utf8_string>
            }
        }
      ]
  }
```
You can test a data path by supplying it as parameters:
```
$ mmdblookup --file /usr/share/GeoIP/GeoIP2-Country.mmdb --ip 8.8.8.8 country names en

  "United States" <utf8_string>
```
It's interesting to note that the data supplied will vary according to the IP address so certain paths will not always be present. Also note that "subdivisions" is an array so can contain multiple values - you can access individual records by supplying a number in the path, for example:
```
$ mmdblookup --file /usr/share/GeoIP/GeoIP2-City.mmdb --ip 2a00:23a8:400b:8f01:edb1:d2ba:aef9:9e9f subdivisions 1 names en

  "Hammersmith and Fulham" <utf8_string>

```