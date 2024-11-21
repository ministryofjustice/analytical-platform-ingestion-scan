import os
import subprocess


def run_command(command):
    result = subprocess.run(  # pylint: disable=subprocess-run-check
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return (
        result.returncode,
        result.stdout.decode("utf-8"),
        result.stderr.decode("utf-8"),
    )


def test_definition_download():
    # Create the directory to store the definitions
    os.makedirs("/tmp/clamav/database", exist_ok=True)

    # Pull the latest definitions
    clamav_config = os.environ.get("LAMBDA_TASK_ROOT", "") + "/freshclam.conf"
    exit_code, stdout, stderr = run_command(
        f'freshclam --user root --config-file="{clamav_config}"'
    )

    if exit_code != 0:
        print(f"Failed to download ClamAV definitions: {stderr}")
        return

    print("ClamAV Definitions downloaded successfully.")

    # Create a test file with content "test"
    test_file_path = os.path.join(os.getcwd(), "test.txt")
    with open(test_file_path, 'w') as test_file:
        test_file.write("test")

    # Create a test file named "test space.txt"
    test_space_file_path = os.path.join(os.getcwd(), "test space.txt")
    with open(test_space_file_path, 'w') as test_space_file:
        test_space_file.write("This file has a space in it's name.")

    # Create an EICAR test file
    eicar_file_path = os.path.join(os.getcwd(), "eicar.txt")
    with open(eicar_file_path, 'w') as eicar_file:
        eicar_file.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    # Scan the test file using the downloaded definitions
    exit_code, stdout, stderr = run_command(
        f"clamscan --database=/tmp/clamav/database {test_file_path}"
    )

    if exit_code == 0:
        print(f"Scan result for {test_file_path}: Clean")
    else:
        print(f"Scan result for {test_file_path}: Infected")
        print(stderr)

    # Scan the EICAR test file
    exit_code, stdout, stderr = run_command(
        f"clamscan --database=/tmp/clamav/database {eicar_file_path}"
    )

    if exit_code == 0:
        print(f"Scan result for {eicar_file_path}: Clean")
    else:
        print(f"Scan result for {eicar_file_path}: Infected")
        print(stderr)

    # Scan the "test space.txt" file
    exit_code, stdout, stderr = run_command(
        f"clamscan --database=/tmp/clamav/database {test_space_file_path}"
    )

    if exit_code == 0:
        print(f"Scan result for {test_space_file_path}: Clean")
    else:
        print(f"Scan result for {test_space_file_path}: Infected")
        print(stderr)


if __name__ == "__main__":
    test_definition_download()
