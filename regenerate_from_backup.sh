#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./regenerate_from_backup.sh <remote_host> <remote_folder_name> <local_store_path>
#
# Example:
#   ./regenerate_from_backup.sh myuser@1.2.3.4 hot_cheese_keys /Users/myusername/hot_cheese_keys
#
# This script will:
#   1. Pull the stored key files from the remote backup into <local_store_path>.
#   2. Pull the 'conf' folder from the remote backup into 'src/conf'.
#
# Assumes the remote side has a structure like:
#   ~/<remote_folder_name>/
#       (all your store files)
#       conf/
#         ssl-cert.pem
#         ssl-key.pem
#         cheese_config.json
#
# Which matches the layout created by the 'simple_backup' script.

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <remote_host> <remote_folder_name> <local_store_path>"
  exit 1
fi

REMOTE_HOST="$1"
REMOTE_FOLDER_NAME="$2"
LOCAL_STORE_PATH="$3"

###############################################################################
# 1) Restore the store folder contents
###############################################################################
echo "Creating local store directory if it doesn't exist..."
mkdir -p "${LOCAL_STORE_PATH}"

echo "Restoring store files from remote..."
# Use rsync to copy only files outside 'conf' to the local store path.
# The --exclude is used so we don't mix the conf folder into our local store path.
rsync -avz --exclude='conf' \
  "${REMOTE_HOST}:~/${REMOTE_FOLDER_NAME}/" \
  "${LOCAL_STORE_PATH}/"

###############################################################################
# 2) Restore the conf folder to 'src/conf'
###############################################################################
echo "Restoring 'conf' folder from remote to 'src/conf'..."
mkdir -p src/conf

rsync -avz \
  "${REMOTE_HOST}:~/${REMOTE_FOLDER_NAME}/conf/" \
  "src/conf/"

echo "Restoration complete!"
echo " - Store files are in: ${LOCAL_STORE_PATH}"
echo " - Config files are in: src/conf/"
