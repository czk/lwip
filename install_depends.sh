#!/usr/bin/env bash

# Copyright 2026
#
# 准备环境安装依赖项
set -e
SCRIPT_DIR="$( dirname "$(realpath "${BASH_SOURCE[0]}")" )"

cp -f ${SCRIPT_DIR}/contrib/examples/example_app/lwipcfg.h.example ${SCRIPT_DIR}/contrib/examples/example_app/lwipcfg.h
sudo npm install -g @anthropic-ai/claude-code
sudo apt update
sudo apt install check -y
