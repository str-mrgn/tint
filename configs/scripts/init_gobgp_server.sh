#!/bin/bash
set -e
BIN_DIR="/root/bin"
CONF_DIR="/root/configs/gobgp"

chmod +x ${BIN_DIR}/* 2>/dev/null || true
ln -sf ${BIN_DIR}/gobgpd /usr/local/bin/gobgpd
ln -sf ${BIN_DIR}/gobgp /usr/local/bin/gobgp

# Start GoBGP daemon for route server
gobgpd -f ${CONF_DIR}/gobgpd_server.conf --log-level=info > /var/log/gobgpd.log 2>&1 &
exit 0
