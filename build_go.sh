#!/bin/sh

set -euo pipefail

cd go_12/
go mod tidy
go build -o stethoscope
