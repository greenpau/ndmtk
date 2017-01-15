#
# Build Docker image:     docker build -t greenpau/ndmtk-docs .
# Run Docker container:   docker run --rm -p 8000:8000 greenpau/ndmtk-docs
#

FROM alpine:latest
MAINTAINER Paul Greenberg @greenpau

RUN apk update && apk add lighttpd
COPY lighttpd.conf /etc/lighttpd/lighttpd.conf
COPY _build/html/ /var/www/localhost/html
EXPOSE 8000
CMD ["/usr/sbin/lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
