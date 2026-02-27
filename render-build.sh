#!/bin/bash
# Render build script - uses pre-built binaries to avoid Rust compilation
# exit on error
set -o errexit

pip install --upgrade pip
pip install --only-binary :all: -r requirements.txt
