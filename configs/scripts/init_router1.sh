#!/bin/bash
set -e
BIN_DIR="/root/bin"
CONF_DIR="/root/configs/gobgp"

chmod +x ${BIN_DIR}/* 2>/dev/null || true
ln -sf ${BIN_DIR}/gobgpd /usr/local/bin/gobgpd
ln -sf ${BIN_DIR}/gobgp /usr/local/bin/gobgp
ln -sf ${BIN_DIR}/tint /usr/local/bin/tint
ln -sf ${BIN_DIR}/srv6-pcc /usr/local/bin/srv6-pcc

# Start GoBGP daemon for router1
gobgpd -f ${CONF_DIR}/gobgpd_router1.conf --log-level=info > /var/log/gobgpd.log 2>&1 &
exit 0
