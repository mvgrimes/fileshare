# syntax=docker/dockerfile:1

FROM golang:1.25-alpine as build

# Add Tini
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod +x /tini

RUN adduser -S -D -H -h /app appuser
WORKDIR /app

COPY ./fileshare-linux-amd64 /app/fileshare
RUN chmod +x /app/fileshare

USER appuser

ENTRYPOINT [ "/tini", "--" ]
CMD ./fileshare bootstrap && ./fileshare server
