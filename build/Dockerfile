# Runtime image. NETY needs raw sockets and interface/route management:
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v nety-data:/data -p 8443:8443 nety:latest
FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates tzdata

FROM scratch
ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.title="NETY" \
      org.opencontainers.image.description="Internal network mapping and VLAN segmentation testing platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=certs /usr/share/zoneinfo /usr/share/zoneinfo
COPY dist/nety-linux-amd64 /nety
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["/nety"]
CMD ["serve", "--data", "/data", "--listen", ":8443"]
