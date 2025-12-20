#!/bin/sh

set -euo pipefail

cd go_11/
go mod tidy
go build -o stethoscope
