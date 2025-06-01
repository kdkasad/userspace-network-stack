#!/usr/bin/env bash

exec unshare --user --net --map-root-user "$@"
