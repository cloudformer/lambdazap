# The scan image: official OWASP ZAP, unchanged, plus the scan runner (lambdazap-scan) and boto3 for S3 / SSM.
# CodeBuild runs one build per scan on it; the buildspec's only command is lambdazap-scan.
FROM ghcr.io/zaproxy/zaproxy:2.16.1

USER root
RUN pip3 install --no-cache-dir --break-system-packages boto3==1.35.99 \
 && mkdir -p /zap/wrk && chown zap:zap /zap/wrk
COPY scan.py /usr/local/bin/lambdazap-scan
COPY zap_hook.py /zap/zap_hook.py
RUN chmod 755 /usr/local/bin/lambdazap-scan
