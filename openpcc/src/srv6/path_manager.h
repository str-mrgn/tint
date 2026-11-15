// SPDX-License-Identifier: MIT
#ifndef PATH_MANAGER_H
#define PATH_MANAGER_H

#include <stdint.h>
#include <netinet/in.h>

// Initpath manager

int path_manager_init(const char *oif_name, int lcblock_bits, int lcnode_bits);

// Handle a PCE-initiated LSP
int path_manager_handle_pcinitiate(const uint8_t *buf, int len);

// Handle a PCUpdate
int path_manager_handle_pcupdate(const uint8_t *buf, int len);

#endif /* PATH_MANAGER_H */
