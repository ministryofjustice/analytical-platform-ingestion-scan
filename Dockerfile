#checkov:skip=CKV_DOCKER_2: HEALTHCHECK not required - AWS Lambda does not support HEALTHCHECK
#checkov:skip=CKV_DOCKER_3: USER not required - A non-root user is used by AWS Lambda
FROM public.ecr.aws/lambda/python:3.13@sha256:9452cd99484f2ac5ac8242449f28bc3c0adc34f6422b47e3cc12a146cdf87813

LABEL org.opencontainers.image.vendor="Ministry of Justice" \
      org.opencontainers.image.authors="Analytical Platform (analytical-platform@digital.justice.gov.uk)" \
      org.opencontainers.image.title="Ingestion Scan" \
      org.opencontainers.image.description="Ingestion scan image for Analytical Platform" \
      org.opencontainers.image.url="https://github.com/ministryofjustice/analytical-platform"

RUN microdnf update \
    && microdnf install --assumeyes \
         clamav1.4-1.4.3-1.amzn2023.0.3.x86_64 \
         clamd1.4-1.4.3-1.amzn2023.0.3.x86_64 \
         tar-2:1.34-1.amzn2023.0.4.x86_64 \
    && microdnf clean all

COPY --chown=nobody:nobody --chmod=0755 src/var/task/ ${LAMBDA_TASK_ROOT}

RUN python -m pip install --no-cache-dir --upgrade pip==24.0 \
    && python -m pip install --no-cache-dir --requirement requirements.txt

CMD ["handler.handler"]
