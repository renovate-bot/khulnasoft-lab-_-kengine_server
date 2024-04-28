FROM alpine:3.18
MAINTAINER Kengine Inc
LABEL kengine.role=system

ENV KENGINE_HTTP_LISTEN_ENDPOINT=8080 \
    KENGINE_ACCESS_TOKEN_EXPIRY_MINUTES=5

ADD kengine_server/auth /auth
ADD kengine_server/cloud_controls /cloud_controls
COPY kengine_server/entrypoint.sh /entrypoint.sh

RUN apk add --no-cache --update bash curl libpcap tar kafkacat postgresql15-client

RUN chmod +x /entrypoint.sh

RUN cd /usr/local/share/ && \
    wget https://github.com/swagger-api/swagger-ui/archive/refs/tags/v4.15.5.tar.gz -O /usr/local/share/swagger-ui.tar.gz && \
    tar -xzf /usr/local/share/swagger-ui.tar.gz -C /usr/local/share/ && \
    mv /usr/local/share/swagger-ui-4.15.5/dist /usr/local/share/swagger-ui && \
    rm -rf /usr/local/share/swagger-ui.tar.gz /usr/local/share/swagger-ui-4.15.5

COPY ./kengine_server/kengine_server /usr/local/bin/kengine_server

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/kengine_server"]
