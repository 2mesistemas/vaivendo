# Dockerfile para o spring boot
FROM openjdk:8-alpine
EXPOSE 9002

## Configuration
#ENV SUPERSET_DEFAULT_HOST 10.203.2.20
#ENV SUPERSET_DEFAULT_PORT 8088
#ENV JASPERSERVER_DEFAULT_HOST 10.203.2.20
#ENV JASPERSERVER_DEFAULT_PORT 8090
#ENV JASPERSERVER_DOMAIN jasperserver-pro
#ENV JASPERSERVER_USERNAME jasperadmin
#ENV JASPERSERVER_PASSWORD jasperadmin

COPY target/analytics-*.jar analytics.jar

ENTRYPOINT ["java","-jar","/analytics.jar", "br.jus.pje.analytics.PjeAnalyticsApplication"]
