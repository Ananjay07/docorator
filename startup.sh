#!/bin/bash

# Exit immediately if a command exits with a non-zero status
# set -e 
# (We don't use set -e globally because we want to print errors for debugging)

echo "----------------------------------------"
echo "Starting Docorator Backend..."
echo "Date: $(date)"
echo "User: $(whoami)"
echo "PWD:  $(pwd)"
echo "----------------------------------------"

# --- 1. Environment Debugging ---
echo "DEBUG: Checking Environment Variables..."
if [ -z "$GEMINI_API_KEY" ]; then
    echo "WARNING: GEMINI_API_KEY is not set!"
else
    echo "INFO: GEMINI_API_KEY is set (Length: ${#GEMINI_API_KEY})"
fi

if [ -z "$SECRET_KEY" ]; then
    echo "WARNING: SECRET_KEY is not set! Using default (unsafe for prod)."
else
    echo "INFO: SECRET_KEY is set."
fi

echo "INFO: WEBSITES_PORT is ${WEBSITES_PORT}"
echo "INFO: PORT (internal) is ${PORT}"

# --- 2. Port Configuration ---
# Azure sets $WEBSITES_PORT, but we need to pass it to uvicorn.
# If WEBSITES_PORT is set, use it. Otherwise default to 8000.
LISTEN_PORT=${WEBSITES_PORT:-8000}
echo "INFO: Application will listen on port: $LISTEN_PORT"

# --- 3. Storage & Permissions ---
# Azure mounts persistent storage at /home when WEBSITES_ENABLE_APP_SERVICE_STORAGE=true
# Our app expects STORAGE_DIR to be writable.
echo "DEBUG: Checking Storage Permissions..."

# Default to /home/data if not set (Recommended for Azure)
export STORAGE_DIR=${STORAGE_DIR:-/home/data}

echo "INFO: data directory is set to: $STORAGE_DIR"

if [ ! -d "$STORAGE_DIR" ]; then
    echo "INFO: Directory $STORAGE_DIR does not exist. Attempting to create..."
    mkdir -p "$STORAGE_DIR"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create $STORAGE_DIR. Check permissions."
    else
        echo "INFO: Created $STORAGE_DIR."
    fi
fi

# Try to write a test file
TEST_FILE="$STORAGE_DIR/write_test_$(date +%s).txt"
touch "$TEST_FILE"
if [ $? -eq 0 ]; then
    echo "SUCCESS: Write permission confirmed on $STORAGE_DIR."
    rm "$TEST_FILE"
else
    echo "CRITICAL FAULT: Cannot write to $STORAGE_DIR. App may crash."
    # We continue anyway, maybe it's just a subdirectory issue
fi

# --- 4. Launch Application ---
echo "----------------------------------------"
echo "Launching Uvicorn..."
echo "----------------------------------------"

# Run Uvicorn
# --host 0.0.0.0 : Bind to all interfaces (required for container)
# --port $LISTEN_PORT : Listen on the port Azure expects
exec python -m uvicorn app.main:app --host 0.0.0.0 --port "$LISTEN_PORT"
