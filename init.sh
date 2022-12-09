#! /bin/bash

./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release.server_only'
docker build -f ci/Dockerfile-envoy -t envoy-io_uring .
