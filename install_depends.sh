#!/usr/bin/env bash

# Copyright 2026
#
# 准备环境安装依赖项
set -e

cp -f /workspaces/lwip/contrib/examples/example_app/lwipcfg.h.example /workspaces/lwip/contrib/examples/example_app/lwipcfg.h
sudo npm install -g @anthropic-ai/claude-code
sudo apt update
sudo apt install check -y
