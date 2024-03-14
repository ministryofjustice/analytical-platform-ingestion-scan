import logging
import os
import subprocess
import tarfile
from datetime import datetime

import boto3
import botocore.exceptions

logger = logging.getLogger()
logger.setLevel("INFO")

s3_client = boto3.client("s3")


def run_command(command):
    result = subprocess.run(  # pylint: disable=subprocess-run-check
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return (
        result.returncode,
        result.stdout.decode("utf-8"),
        result.stderr.decode("utf-8"),
    )


def definition_upload():
    # Create the directory to store the definitions
    try:
        os.makedirs("/tmp/clamav/database", exist_ok=True)
    except OSError as e:
        logger.error("Failed to create directory: %s", e)
        raise

    # Pull the latest definitions
    clamav_config = os.environ.get("LAMBDA_TASK_ROOT") + "/freshclam.conf"
    user_id = os.getuid()

    freshclam_run = run_command(
        f'freshclam --no-warnings --user {user_id} --config-file="{clamav_config}"'
    )

    if freshclam_run[0] != 0:
        logger.error("Failed to run freshclam: %s", freshclam_run[2])
        raise OSError(f"Failed to run freshclam: {freshclam_run[2]}")

    # Archive the definitions
    try:
        with tarfile.open("/tmp/clamav/clamav.tar.gz", "w:gz") as tar:
            tar.add("/tmp/clamav/database")
    except OSError as e:
        logger.error("Failed to archive definitions: %s", e)
        raise

    # Upload the definitions to S3
    bucket_name = os.environ.get("CLAMAV_DEFINITON_BUCKET_NAME")
    if not bucket_name:
        raise ValueError(
            "The required environment variable CLAMAV_DEFINITON_BUCKET_NAME is not set."
        )

    try:
        s3_client.upload_file("/tmp/clamav/clamav.tar.gz", bucket_name, "clamav.tar.gz")
    except botocore.exceptions.ClientError as e:
        logger.error("Failed to upload ClamAV definitions: %s", e)
        raise

    return {
        "statusCode": 200,
        "body": "Successfully uploaded ClamAV definitions to S3.",
    }


def definition_download():
    # Create the directory to store the definitions
    try:
        os.makedirs("/tmp/clamav/database", exist_ok=True)
    except OSError as e:
        logger.error("Failed to create directory: %s", e)
        raise

    # Download the definitions from S3
    bucket_name = os.environ.get("CLAMAV_DEFINITON_BUCKET_NAME")
    if not bucket_name:
        raise ValueError(
            "The required environment variable CLAMAV_DEFINITON_BUCKET_NAME is not set."
        )

    try:
        with tarfile.open("/tmp/clamav/clamav.tar.gz", "r:gz") as tar:
            tar.extractall(path="/tmp/clamav/database", filter="data")
    except OSError as e:
        logger.error("Failed to extract definitions: %s", e)
        raise


def scan(event):
    object_key = event["Records"][0]["s3"]["object"]["key"]
    object_name = object_key.split("/")[-1]

    # Create the directory for running the scan
    try:
        os.makedirs("/tmp/clamav/scan", exist_ok=True)
    except OSError as e:
        logger.error("Failed to create directory: %s", e)
        raise

    # Download the file to scan
    landing_bucket_name = os.environ.get("LANDING_BUCKET_NAME")
    if not landing_bucket_name:
        raise ValueError(
            "The required environment variable LANDING_BUCKET_NAME is not set."
        )

    try:
        s3_client.download_file(
            landing_bucket_name, object_key, f"/tmp/clamav/scan/{object_name}"
        )
    except botocore.exceptions.ClientError as e:
        logger.error("Failed to download file: %s", e)
        raise

    # Scan the file
    scan_time = datetime.now().isoformat()

    logger.info("Scanning file %s at %s", object_name, scan_time)

    clam_scan_run = os.system(
        f"clamscan --database=/tmp/clamav/database /tmp/clamav/scan/{object_name}"
    )

    if clam_scan_run == 0:
        logger.info("File %s is clean.", object_name)
        # move_to_processed(object_key, scan_time)
    elif clam_scan_run == 1:
        logger.warning("File %s is infected.", object_name)
        # move_to_infected(object_key, scan_time)
    else:
        logger.error("Failed to scan file %s.", object_name)
        raise ValueError(f"Failed to scan file {object_name}.")


def handler(event, context):  # pylint: disable=unused-argument
    mode = os.environ.get("MODE")
    if not mode:
        raise ValueError(
            "The required environment variable MODE is not set. Please set it to either 'definition-upload' or 'scan'."
        )
    if mode == "definition-upload":
        logger.info("Mode is definition-upload")
        definition_upload()
    elif mode == "scan":
        logger.info("Mode is scan")
        definition_download()
        # scan(event)
    else:
        raise ValueError(f"Invalid mode: {mode}")
