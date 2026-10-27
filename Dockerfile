# Sihti – DNS-suodatin. Toimii Raspberry Pi:llä (arm64, arm/v7) ja tavallisilla koneilla (amd64).
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="Sihti" \
      org.opencontainers.image.description="Kevyt DNS-suodatin kotiverkkoon ja pientoimistoon" \
      org.opencontainers.image.vendor="Zarm Instruments"

# openssl: HTTPS-varmenteiden luonti. tzdata: TZ-aikavyöhyke lokiin. setcap: portin 53 sitominen ilman root-oikeuksia
# myös silloin, kun kontti ajetaan isäntäkoneen verkossa (network_mode: host).
RUN apk add --no-cache openssl tzdata \
 && { apk add --no-cache --virtual .caps libcap-setcap \
      || apk add --no-cache --virtual .caps libcap-utils \
      || apk add --no-cache --virtual .caps libcap; } \
 && setcap cap_net_bind_service=+ep "$(readlink -f /usr/local/bin/python3)" \
 && apk del .caps \
 && addgroup -S -g 10053 sihti \
 && adduser -S -D -H -u 10053 -G sihti sihti \
 && mkdir -p /data && chown sihti:sihti /data

WORKDIR /app
COPY sihti/ /app/sihti/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIHTI_CONFIG=/data/sihti.json \
    SIHTI_DATA_DIR=/data

USER sihti
VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 4000/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python3", "-m", "sihti.healthcheck"]

CMD ["python3", "-m", "sihti"]
