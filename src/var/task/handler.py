import json
import os
import subprocess
from datetime import datetime
import traceback 

import boto3
import botocore.exceptions

s3_client = boto3.client("s3")
scan_time = datetime.now().isoformat()

def run_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return (result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8"))

def definition_download():
    os.makedirs("/tmp/clamav/database", exist_ok=True)
    bucket_name = os.environ.get("CLAMAV_DEFINITON_BUCKET_NAME")
    if not bucket_name:
        raise ValueError("CLAMAV_DEFINITON_BUCKET_NAME environment variable not set.")
    s3_client.download_file(bucket_name, "clamav.tar.gz", "/tmp/clamav/clamav.tar.gz")
    print("Successfully downloaded ClamAV definitions from S3.")
    run_command("tar --extract --gzip --verbose --file=/tmp/clamav/clamav.tar.gz -C /tmp/clamav/database")
    print("Successfully extracted ClamAV definitions.")

def run_scan(file_path):
    """
    Runs the clamscan command on a file.
    Returns: A tuple of (status, detail)
             e.g., ("clean", None) or ("infected", "Win.Test.EICAR_HDB-1")
    """
    exit_code, stdout, stderr = run_command(
        f"clamscan --database=/tmp/clamav/database \"{file_path}\""
    )
    
    print(stdout)
    if stderr:
        print(f"ClamAV stderr: {stderr}")
    
    if exit_code == 0:
        return ("clean", None)
    
    if exit_code == 1:
        # Parse stdout for the virus name
        virus_name = "Unknown"
        for line in stdout.split('\n'):
            if line.strip().endswith(" FOUND"):
                try:
                    # Parse "filename: virus-name FOUND"
                    virus_name = line.split(': ')[1].replace(' FOUND', '').strip()
                    break # Found it
                except Exception:
                    pass # Failed to parse, will use "Unknown"
        return ("infected", virus_name)
    
    # ClamAV returned an error code (like 2)
    raise Exception(f"ClamAV scan error. Exit code: {exit_code}. STDERR: {stderr}")

def update_tags(bucket_name: str, object_key: str, status: str, detail: str = None):
    """
    Adds tags for the result of a file scan to an object.
    'status' is "clean", "infected", or "error".
    'detail' is the virus name or error message.
    """
    try:
        response = s3_client.get_object_tagging(Bucket=bucket_name, Key=object_key)
        tags = response.get("TagSet", [])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchTaggingSet':
            tags = []
        else:
            print(f"Failed to get tags for {object_key}: {e}")
            tags = [] # Default to empty list on other errors

    additional_tags = {
        "scan-result": status,
        "scan-time": scan_time,
    }

    if status == "infected" and detail:
        additional_tags["virus-name"] = detail
    elif status == "error" and detail:
        # S3 tags cannot contain newlines
        safe_error = detail.replace('\n', ' ').replace('\r', ' ')
        additional_tags["scan-error"] = safe_error[:250]

    # Remove any existing tags with the same key
    tags_to_keep = [t for t in tags if t['Key'] not in additional_tags]
    tags_to_keep.extend([{"Key": key, "Value": value} for key, value in additional_tags.items()])

    s3_client.put_object_tagging(
        Bucket=bucket_name,
        Key=object_key,
        Tagging={"TagSet": tags_to_keep},
    )

def move_and_tag_files(destination_bucket: str, scan_results_map: dict):
    """
    Moves files and applies individual tags based on the scan_results_map.
    scan_results_map = {
        "key1": ("clean", None),
        "key2": ("infected", "EICAR-Test-File"),
        "key3": ("error", "ClamAV scan error")
    }
    """
    landing_bucket_name = os.environ["LANDING_BUCKET_NAME"]
    
    for object_key, (status, detail) in scan_results_map.items():
        try:
            print(f"Moving {object_key} to {destination_bucket} with status: {status}")
            copy_source = {"Bucket": landing_bucket_name, "Key": object_key}
            
            s3_client.copy_object(
                Bucket=destination_bucket, CopySource=copy_source, Key=object_key
            )
            s3_client.delete_object(
                Bucket=landing_bucket_name, Key=object_key
            )
            
            # Tag the object in its new location
            update_tags(
                bucket_name=destination_bucket,
                object_key=object_key,
                status=status,
                detail=detail
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] in ['404', 'NoSuchKey']:
                print(f"File {object_key} was already processed by a concurrent invocation.")
            else:
                print(f"FATAL: Could not move or tag {object_key}. Error: {e}")
                traceback.print_exc()

def handler(event, context):
    print("Received event:", event)
    
    landing_bucket = os.environ["LANDING_BUCKET_NAME"]
    processed_bucket = os.environ["PROCESSED_BUCKET_NAME"]
    quarantine_bucket = os.environ["QUARANTINE_BUCKET_NAME"]
    
    file_keys_to_process = []
    folder_keys_to_move = []
    
    try:
        triggering_object_key = event["Records"][0]["s3"]["object"]["key"]
        
        if not triggering_object_key.endswith('_commit.json'):
            print(f"Ignoring non-commit-file trigger: {triggering_object_key}")
            return {"statusCode": 200, "body": json.dumps({"message": "Trigger ignored."})}
            
        directory = os.path.dirname(triggering_object_key)
        prefix = directory + "/" if directory else ""
        
        # List all files and folder objects in the batch
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=landing_bucket, Prefix=prefix):
            if "Contents" in page:
                for obj in page["Contents"]:
                    if not obj['Key'].endswith('/'):
                        file_keys_to_process.append(obj['Key'])
                    else:
                        folder_keys_to_move.append(obj['Key']) # Track folder objects

        if not file_keys_to_process:
            raise Exception(f"No files found in batch prefix: {prefix}")
            
        print(f"Processing batch. Prefix: {prefix}. Files: {file_keys_to_process}")

        # Setup scanner
        os.makedirs("/tmp/clamav/scan", exist_ok=True)
        definition_download()
        
        # Scan all files and build a results map
        scan_results_map = {}
        is_batch_infected_or_error = False
        
        for object_key in file_keys_to_process:
            try:
                # The commit file is safe, just mark it as clean
                if object_key.endswith('_commit.json'):
                    scan_results_map[object_key] = ("clean", None)
                    continue

                print(f"Scanning file: {object_key}")
                local_file_path = f"/tmp/clamav/scan/{os.path.basename(object_key)}"
                s3_client.download_file(landing_bucket, object_key, local_file_path)
                
                status, detail = run_scan(local_file_path)
                scan_results_map[object_key] = (status, detail)
                
                if status == "infected":
                    print(f"INFECTED: {object_key}, Virus: {detail}")
                    is_batch_infected_or_error = True
                else:
                    print(f"CLEAN: {object_key}")
                
                os.remove(local_file_path)
                
            except Exception as e:
                # Handle error on a *single file scan*
                print(f"ERROR scanning {object_key}: {e}")
                traceback.print_exc()
                scan_results_map[object_key] = ("error", str(e))
                is_batch_infected_or_error = True

        # Move the entire batch based on the final result
        if is_batch_infected_or_error:
            print("Batch contains infected or errored files. Moving all files to quarantine.")
            move_and_tag_files(quarantine_bucket, scan_results_map)
            # Also move the folder objects to quarantine
            for key in folder_keys_to_move:
                print(f"Moving folder {key} to quarantine")
                s3_client.copy_object(Bucket=quarantine_bucket, CopySource={"Bucket": landing_bucket, "Key": key}, Key=key)
                s3_client.delete_object(Bucket=landing_bucket, Key=key)
        else:
            print("Batch is clean. Moving all files to processed.")
            move_and_tag_files(processed_bucket, scan_results_map)
            # Delete the empty folder objects from landing
            for key in folder_keys_to_move:
                print(f"Deleting clean folder object: {key}")
                s3_client.delete_object(Bucket=landing_bucket, Key=key)

    except Exception as e:
        # Catch-all for *system* errors (e.g., definition download fails)
        print(f"A system error occurred during batch processing: {e}")
        traceback.print_exc()
        
        # Create an error map for all files we know about
        error_results_map = {}
        for key in file_keys_to_process:
            if key not in error_results_map:
                error_results_map[key] = ("error", str(e))
        
        if not error_results_map: # Failed before we listed files
             error_results_map[event["Records"][0]["s3"]["object"]["key"]] = ("error", str(e))

        print("Moving all known batch files to quarantine due to system error.")
        move_and_tag_files(quarantine_bucket, error_results_map)
        
        # Also move the folder objects to quarantine
        for key in folder_keys_to_move:
            print(f"Moving error folder {key} to quarantine")
            s3_client.copy_object(Bucket=quarantine_bucket, CopySource={"Bucket": landing_bucket, "Key": key}, Key=key)
            s3_client.delete_object(Bucket=landing_bucket, Key=key)
        
        return {"statusCode": 500, "body": json.dumps({"message": "An error occurred"})}

    return {"statusCode": 200, "body": json.dumps({"message": "Batch processed successfully"})}