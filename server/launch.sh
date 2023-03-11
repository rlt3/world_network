#!/bin/bash

if [ "$EUID" -eq 0 ]
    then echo "Don't run as root so the process isn't running as root."
    exit 1
fi

if [ -z "${WORLD_CERT}" ] || [ -z "${WORLD_PRIV}" ] || [ -z "${WORLD_DH}" ]; then
    echo "Failed starting: non-existing TLS credentials!\n Make sure that you have the WORLD_CERT, WORLD_PRIV and WORLD_DH environment variables set!"
    exit 1
fi

# environment only exists for this process only
export cert=$(sudo cat $WORLD_CERT)
export priv=$(sudo cat $WORLD_PRIV)
export dh=$(sudo cat $WORLD_DH)
./socketserver
