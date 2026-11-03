# Stage 4 sandbox: the image every case's pytest run executes in.
# See stages/safety.py (_docker_command) for the limits applied at `docker run`.
#
#   docker build -t aieval-sandbox sandbox
#
# The slim Debian base already ships the tools the dataset's CWE-78 cases call
# (sh, ls, du, df, grep, gzip, tar, uname, wc, echo). Cases import only the
# standard library and pytest, so nothing else is installed.
FROM python:3.12-slim

RUN pip install --no-cache-dir "pytest==8.3.5" \
 && useradd --uid 1000 --create-home sandbox

USER 1000:1000
WORKDIR /case
