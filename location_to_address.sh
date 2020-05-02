#!/usr/bin/env bash
gdb $1 -quiet -batch -ex "info line $2"
