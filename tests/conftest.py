"""Fakes for the AWS clients the Lambda and the scanner use: no AWS account, no Docker."""
import base64
import datetime
import io
import json
import os
import sys

from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "client"), os.path.join(ROOT, "client", "lambdazap", "image")]
os.environ.update(AWS_DEFAULT_REGION="us-east-2", HTTP_AUTH="1", USER_NAME="admin", PASSWORD="a-password-of-16+chars",
                  ALLOWED_TARGETS=json.dumps(["example.com", "app.example.org:8443", "*.example.net"]),
                  BUCKET="test-reports", PROJECT="test-scanner", LOG_GROUP="/aws/codebuild/test-scanner",
                  IDLE_SHUTDOWN_MINUTES="15", MAX_SESSION_MINUTES="480", MAX_SCANNERS="2", COMPUTE_TYPE="BUILD_GENERAL1_SMALL")

SCANNER_ID = "0b6f7c1e-1111-4222-8333-944455556666"
STARTED = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)   # when the fake builds start


def _error(code, op):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class FakeCodeBuild:
    """One project; start_build makes an IN_PROGRESS build; limit = the project's concurrent build limit."""

    class exceptions:
        class AccountLimitExceededException(Exception):
            pass

    def __init__(self, limit=2):
        self.builds, self.limit, self.started = {}, limit, []

    def start_build(self, projectName, environmentVariablesOverride, computeTypeOverride="BUILD_GENERAL1_SMALL"):
        if sum(b["buildStatus"] == "IN_PROGRESS" for b in self.builds.values()) >= self.limit:
            raise self.exceptions.AccountLimitExceededException("Cannot have more than N builds in queue")
        build_id = f"{projectName}:{SCANNER_ID if not self.builds else f'{len(self.builds):08x}-0000-4000-8000-000000000000'}"
        self.started.append({"env": environmentVariablesOverride, "compute_type": computeTypeOverride})
        self.builds[build_id] = {"id": build_id, "buildStatus": "IN_PROGRESS", "currentPhase": "PROVISIONING",
                                 "startTime": STARTED.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "environment": {"environmentVariables": environmentVariablesOverride, "computeType": computeTypeOverride},
                                 "logs": {"streamName": build_id.split(":")[1]}}
        return {"build": self.builds[build_id]}

    def batch_get_builds(self, ids):
        return {"builds": [self.builds[i] for i in ids if i in self.builds]}

    def list_builds_for_project(self, projectName, sortOrder):
        return {"ids": list(reversed(self.builds))}

    def stop_build(self, id):
        self.builds[id]["buildStatus"] = "STOPPED"
        return {"build": self.builds[id]}


class FakeLogs:
    """GetLogEvents / FilterLogEvents over one list of lines per stream; a line's time is its index."""

    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self):
        self.streams = {}

    def get_log_events(self, logGroupName, logStreamName, startFromHead, nextToken=None):
        if logStreamName not in self.streams:
            raise self.exceptions.ResourceNotFoundException(logStreamName)
        lines = self.streams[logStreamName]
        start = int(nextToken[2:]) if nextToken else 0
        return {"events": [{"message": m + "\n"} for m in lines[start:]], "nextForwardToken": f"f/{len(lines)}"}

    def filter_log_events(self, logGroupName, logStreamNames, filterPattern, startTime, nextToken=None):
        word = filterPattern.strip('"')
        lines = self.streams.get(logStreamNames[0], [])
        return {"events": [{"eventId": f"{s}-{i}", "timestamp": i, "message": m + "\n"}
                           for s in logStreamNames for i, m in enumerate(lines) if word in m and i >= startTime]}


class FakeS3:
    class exceptions:
        NoSuchKey = type("NoSuchKey", (Exception,), {})

    def __init__(self):
        self.objects = {}

    def get_paginator(self, name):
        objects = self.objects

        class Paginator:
            def paginate(self, Bucket, Prefix):
                yield {"Contents": [{"Key": k, "ETag": f'"{len(objects[k])}"'} for k in sorted(objects) if k.startswith(Prefix)]}
        return Paginator()

    def generate_presigned_url(self, op, Params, ExpiresIn):
        return f"https://signed/{Params['Key']}?expires={ExpiresIn}"

    def upload_file(self, path, bucket, key, ExtraArgs=None):
        with open(path, "rb") as fh:
            self.objects[key] = fh.read()

    def put_object(self, Bucket, Key, Body, ContentType=None, IfNoneMatch=None):
        if IfNoneMatch == "*" and Key in self.objects:
            raise _error("PreconditionFailed", "PutObject")
        self.objects[Key] = Body

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise self.exceptions.NoSuchKey(Key)
        return {"Body": io.BytesIO(self.objects[Key])}


def basic(user="admin", password="a-password-of-16+chars"):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
