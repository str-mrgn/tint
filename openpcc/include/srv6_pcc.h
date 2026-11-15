// SPDX-License-Identifier: MIT
#ifndef SRV6_PCC_H
#define SRV6_PCC_H

#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

// Global shutdown flag - shared between main and threads
extern volatile sig_atomic_t g_shutdown;

// Version
#define SRV6_PCC_VERSION "0.1.0"

// Constants
#define MAX_SID_LIST_SIZE 32
#define PCEP_DEFAULT_PORT 4189

// PCC configuration
struct pcc_config {
    char pce_addr_str[64];          // PCE address string (IPv4/IPv6)
    uint16_t pce_port;
    char local_addr_str[64];        // Local address string (IPv4/IPv6)
    uint8_t keepalive_timer;
    uint8_t dead_timer;
    int stateful;                   // -1: auto-detect, 0: disabled, 1: enabled
    char *config_file;
    int af_family;                  // AF_INET or AF_INET6
};

// Function prototypes
int pcc_init(struct pcc_config *config);
int pcc_connect(void);
int pcc_send_raw(const uint8_t *buf, int len);  // generic send (thread-safe)
int pcc_cleanup(void);

#endif /* SRV6_PCC_H */
