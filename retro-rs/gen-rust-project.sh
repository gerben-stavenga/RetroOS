#!/bin/bash
# Regenerate rust-project.json for rust-analyzer
# Run this after adding/removing crates or changing dependencies

set -e
bazelisk run @rules_rust//tools/rust_analyzer:gen_rust_project \
    --platforms=@platforms//host \
    -- //kernel:kernel //lib:lib //boot:boot //apps/init:init_lib

echo "rust-project.json regenerated. Restart rust-analyzer to pick up changes."
