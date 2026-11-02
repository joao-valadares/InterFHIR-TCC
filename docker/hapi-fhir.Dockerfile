FROM eclipse-temurin:17-jdk@sha256:91011320978c10ec51d2cde1eb6f616db6d2a739a0e521096c343dd3fed9abe6 AS healthcheck-builder

COPY docker/FhirMetadataHealthcheck.java /src/FhirMetadataHealthcheck.java
RUN javac -d /out /src/FhirMetadataHealthcheck.java

FROM hapiproject/hapi:v7.6.0@sha256:4771a178e764896c83881c1b3a52bd487e53d06e1acc3653ea0db0c6f6b2b8a1

ENV HAPI_FHIR_FHIR_VERSION=R4

COPY --from=healthcheck-builder \
  /out/FhirMetadataHealthcheck.class \
  /opt/interfhir-healthcheck/FhirMetadataHealthcheck.class
