#!/bin/sh

cd go/
go mod tidy
go get stethoscope
go build -o stethoscope
