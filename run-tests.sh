#!/bin/bash

set -e

export INDEX_DIR=./e2e-state/index
export SAMPLES_DIR=./e2e-state/samples

docker-compose -f docker-compose.yml -f docker-compose.test.yml down -v
rm -rf e2e-state/
docker-compose -f docker-compose.yml -f docker-compose.test.yml up --build --exit-code-from tests
