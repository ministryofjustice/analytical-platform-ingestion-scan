---
description: "Update the Lambda base image digest and pinned DNF and Python package versions and open a pull request"
tools:
  - "search/codebase"
  - "search"
  - "edit/editFiles"
  - "execute/runInTerminal"
  - "execute/getTerminalOutput"
---

# Maintenance

Perform maintenance on the Docker image, pinned DNF packages, and pinned Python dependencies for this repository. Update the Lambda base image digest and pinned package versions together, and open a single pull request. Read the current image, tag, and package list from the repository; do not assume specific versions.

## Objective

In one pull request, for the image and packages already declared in this repository:

1. Update the pinned base image digest to the latest published digest for the image and tag in the `FROM` line in `Dockerfile` for `linux/amd64`.
2. Refresh pinned DNF package versions in `Dockerfile` using `microdnf repoquery` against the Lambda base image for `linux/amd64`.
3. Refresh pinned Python dependency versions in `src/var/task/requirements.txt`.
4. If the pinned `pip` version in `Dockerfile` is no longer current, update it as part of the same change.
5. If version assertions are affected, update `test/container-structure-test.yml` to keep expected outputs aligned.

Always read current values from source files before updating.

## Required Outcome

1. Create a single maintenance branch.
2. Update the Lambda base image digest in the `FROM` line in `Dockerfile`.
3. Update pinned DNF package versions in `Dockerfile`.
4. Update pinned Python dependency versions in `src/var/task/requirements.txt`.
5. Update the pinned `pip` version in `Dockerfile` if needed.
6. Update `test/container-structure-test.yml` if expected command output changes.
7. Commit changes using Conventional Commits.
8. Push the branch and open a pull request with a clear title and description.

## Execution Steps

1. Create a maintenance branch.

   ```bash
   git checkout -b "chore/maintenance-dockerfile-$(date +%Y%m%d-%H%M%S)"
   ```

2. Update the base image digest.

   - Read the base image reference (`<image>:<tag>`) from the `FROM` line in `Dockerfile`.
   - Pull that exact image for `linux/amd64`.

   ```bash
   IMAGE="$(grep -oP '(?<=^FROM )[^@[:space:]]+' Dockerfile)"
   docker pull --platform linux/amd64 "$IMAGE"
   ```

   - Retrieve the current repository digest.

   ```bash
   docker image inspect --format='{{ index .RepoDigests 0 }}' "$IMAGE"
   ```

   - Update the `@sha256:...` digest in `Dockerfile`, keeping image repository and tag unchanged.

3. Update pinned DNF packages.

   - Read the DNF package names and current pinned versions from the `microdnf install` command in `Dockerfile`.
   - Start a container from the same Lambda image and tag in the `FROM` line, for `linux/amd64`, then refresh repository metadata and query each package name. For example:

   ```bash
   docker run -it --rm --platform linux/amd64 --entrypoint /bin/bash public.ecr.aws/lambda/python:3.13

   microdnf update
   microdnf repoquery clamav1.5
   microdnf repoquery clamd1.5
   microdnf repoquery tar
   ```

   Replace the example image and package names with those read from `Dockerfile`. Use the latest compatible versions reported by the repository, and update the full pinned package versions in `Dockerfile`, including the architecture suffix where present.

4. Update pinned Python dependencies.

   - Read pinned packages from `src/var/task/requirements.txt`.
   - Update versions to the latest compatible values while preserving the same package names.
   - Keep all dependencies pinned with explicit versions.

5. Review `Dockerfile` and `src/var/task/requirements.txt` to confirm package names and image tag are unchanged (only digest and versions may differ).

6. If any version assertions are affected, update `test/container-structure-test.yml` accordingly.

7. Commit the changes using [Conventional Commits](https://www.conventionalcommits.org/) (`build` type).

8. Push the branch and open the pull request with GitHub CLI.

   - The `git commit`, `git push`, and `gh` steps need local Git/GitHub credentials and network access.
   - Set an explicit PR title: a Conventional Commit `build:` summary matching the commit.
   - Write PR description to a temporary file and pass it with `--body-file`.

   ```bash
   git push -u origin <branch>
   gh pr create --base main --head <branch> --title "<title>" --body-file <body-file>
   ```

   - Report the URL of the created pull request.

## Guardrails

- Keep the base image repository and tag unchanged; only update the digest.
- Keep platform assumption aligned to `linux/amd64`.
- Do not add or remove DNF packages; keep package names unchanged and update only their pinned versions.
- Do not add or remove Python packages.
- Keep all package installs pinned to explicit versions.
- Deliver updates in one branch and one pull request.
- Use Conventional Commits (`build` type) for commit message and PR title.