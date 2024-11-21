.PHONY: build debug test-definition-download test-scan test-definition-upload


IMAGE_NAME ?= analytical-platform.service.justice.gov.uk/ingestion-scan
IMAGE_TAG  ?= local

build:
	docker build --platform linux/amd64 --file Dockerfile --tag $(IMAGE_NAME):$(IMAGE_TAG) .

debug: build
	docker run -it --rm \
		--platform linux/amd64 \
		--hostname ingestion-scan \
		--name analytical-platform-ingestion-scan \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(IMAGE_TAG)

test-definition-download: build
	docker run --rm \
		--platform linux/amd64 \
		--name analytical-platform-ingestion-scan-test-download \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		python test_definition_download.py

test-scan: build
	docker run --rm \
		--platform linux/amd64 \
		--name analytical-platform-ingestion-scan-test-scan \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		python test_scan.py

test-definition-upload: build
	docker run --rm \
		--platform linux/amd64 \
		--name analytical-platform-ingestion-scan-test-upload \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		python test_definition_upload.py

