LOCAL_PORT ?= 8888
PACKAGE_NAME ?= ngx_http_geoip2_module
CONTAINER_NAME ?= $(PACKAGE_NAME)-build

all: clean container run

clean:
	docker rmi -f $(CONTAINER_NAME)
	docker rm -f $(CONTAINER_NAME)

container: source
	docker buildx build --build-arg GEOIPUPDATE_ACCOUNT_ID --build-arg GEOIPUPDATE_EDITION_IDS --secret=type=env,id=GEOIPUPDATE_LICENSE_KEY,src=GEOIPUPDATE_LICENSE_KEY --network=host -t "$(CONTAINER_NAME)" .
	docker create --name "$(CONTAINER_NAME)" "$(CONTAINER_NAME)"

run:
	docker run -p "$(LOCAL_PORT):80" -it "$(CONTAINER_NAME)"

source:
	mkdir -p ./source
	find .. -maxdepth 1 -type f -exec cp -v {} source \;

.PHONY: clean container run source
