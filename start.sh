#!/bin/bash
# Run on Linux (or double-click from a file manager that runs scripts) to start B24-engine.
cd "$(dirname "$0")" || exit 1
npm run launch
