Description
===========

**ngx_http_geoip2_module** - creates variables with values from the maxmind geoip2 databases based on the client IP (default) or from a specific variable (supports both IPv4 and IPv6)

The module now supports nginx streams and can be used in the same way the http module can be used.

## Installing

### Using prebuilt packages for stable NGINX (CentOS / RHEL)

First install RPM repository.

#### For CentOS 6:

    sudo yum -y install https://extras.getpagespeed.com/release-el6-latest.rpm

#### For CentOS 7:

    sudo yum -y install https://extras.getpagespeed.com/release-el7-latest.rpm

Then, to install NGINX and the GeoIP2 dynamic module, you would run:

    sudo yum -y install nginx nginx-module-geoip2

Then add the following at the top of your `/etc/nginx/nginx.conf`:

    load_module modules/ngx_http_geoip2_module.so;

More instructions on using GeoIP2 free databases in RHEL 7 can be found [here](https://www.getpagespeed.com/server-setup/nginx/upgrade-to-geoip2-with-nginx-on-centos-rhel-7).

### Using prebuilt packages (Ubuntu / Debian)

Pre-built packages for this module are freely available from the GetPageSpeed repository.

```bash
# Install the repository keyring
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://extras.getpagespeed.com/deb-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/getpagespeed.gpg >/dev/null

# Add the repository (Ubuntu example - replace 'ubuntu' and 'jammy' for your distro)
echo "deb [signed-by=/etc/apt/keyrings/getpagespeed.gpg] https://extras.getpagespeed.com/ubuntu jammy main" \
  | sudo tee /etc/apt/sources.list.d/getpagespeed-extras.list

# Install nginx and the module
sudo apt-get update
sudo apt-get install nginx nginx-module-geoip2
```

Alternatively, you can use `lsb_release` to auto-detect your distribution:

```bash
echo "deb [signed-by=/etc/apt/keyrings/getpagespeed.gpg] https://extras.getpagespeed.com/$(lsb_release -is | tr '[A-Z]' '[a-z]') $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/getpagespeed-extras.list
```

The module is automatically enabled after installation. Supported distributions include Debian 12/13 and Ubuntu 20.04/22.04/24.04 (both amd64 and arm64).

See [the complete setup instructions](https://apt-nginx-extras.getpagespeed.com/apt-setup/).

### Compilation (other platforms)

First install [libmaxminddb](https://github.com/maxmind/libmaxminddb) as described in its [README.md
file](https://github.com/maxmind/libmaxminddb/blob/main/README.md#installing-from-a-tarball).

#### Download nginx source
```
wget http://nginx.org/download/nginx-VERSION.tar.gz
tar zxvf nginx-VERSION.tar.gz
cd nginx-VERSION
```

##### To build as a dynamic module (nginx 1.9.11+):
```
./configure --with-compat --add-dynamic-module=/path/to/ngx_http_geoip2_module
make modules
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

##### If you need stream support, make sure to compile with stream:
```
./configure --add-dynamic-module=/path/to/ngx_http_geoip2_module --with-stream
OR
./configure --add-module=/path/to/ngx_http_geoip2_module --with-stream
```


## Download Maxmind GeoLite2 Database (optional)
The free GeoLite2 databases are available from [Maxminds website](http://dev.maxmind.com/geoip/geoip2/geolite2/) (requires signing up)

## Example Usage:
```
http {
    ...
    geoip2 /etc/maxmind-country.mmdb {
        auto_reload 5m;
        $geoip2_metadata_country_build metadata build_epoch;
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

##### Metadata:
Retrieve metadata regarding the geoip database.
```
$variable_name metadata <field>
```
Available fields:
  - build_epoch: the build timestamp of the maxmind database.
  - last_check: the last time the database was checked for changes (when using auto_reload)
  - last_change: the last time the database was reloaded (when using auto_reload)

##### Autoreload (default: disabled):
Enabling auto reload will have nginx check the modification time of the database at the specified
interval and reload it if it has changed.
```
auto_reload <interval>
```

##### GeoIP:
```
$variable_name [default=<value] [source=$variable_with_ip] path ...
```
If default is not specified, the variable will be empty if not found.

If source is not specified, $remote_addr will be used to perform the lookup.

To find the path of the data you want (eg: country names en), use the [mmdblookup tool](https://maxmind.github.io/libmaxminddb/mmdblookup.html):

```
$ mmdblookup --file /usr/share/GeoIP/GeoIP2-Country.mmdb --ip 8.8.8.8

  {
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
          }
      }
  }

$ mmdblookup --file /usr/share/GeoIP/GeoIP2-Country.mmdb --ip 8.8.8.8 country names en

  "United States" <utf8_string>
```

This translates to:

```
$country_name "default=United States" source=$remote_addr country names en
```

##### Additional Commands:
These commands works the same as the original ngx_http_geoip_module documented here: http://nginx.org/en/docs/http/ngx_http_geoip_module.html#geoip_proxy.

However, if you provide the `source=$variable_with_ip` option on a variable, these settings will be ignored for that particular variable.

```
geoip2_proxy < cidr >
```
Defines trusted addresses.  When a request comes from a trusted address, an address from the "X-Forwarded-For" request header field will be used instead.

```
geoip2_proxy_recursive < on | off >
```
If recursive search is disabled then instead of the original client address that matches one of the trusted addresses, the last address sent in "X-Forwarded-For" will be used. If recursive search is enabled then instead of the original client address that matches one of the trusted addresses, the last non-trusted address sent in "X-Forwarded-For" will be used.
