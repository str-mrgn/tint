// SPDX-License-Identifier: MIT
#ifndef TYPES_COMMON_H
#define TYPES_COMMON_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>

// PCEP common header (RFC 5440 Section 6.1)
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | Ver |  Flags  |  Message-Type |       Message-Length          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct pcep_common_header {
    uint8_t ver_flags;      // Version (3 bits) + Flags (5 bits)
    uint8_t message_type;   // Message-Type (8 bits)
    uint16_t message_length; // Message-Length (16 bits) in network byte order
} __attribute__((packed));

#define PCEP_VERSION 1

// PCEP message types
enum pcep_message_type {
    PCEP_MSG_OPEN = 1,
    PCEP_MSG_KEEPALIVE = 2,
    PCEP_MSG_PCREQ = 3,
    PCEP_MSG_PCREP = 4,
    PCEP_MSG_PCNTF = 5,
    PCEP_MSG_PCERR = 6,
    PCEP_MSG_CLOSE = 7,
    PCEP_MSG_PCRPT = 10,
    PCEP_MSG_PCUPD = 11,
    PCEP_MSG_PCINITIATE = 12,
};

// PCEP object header (RFC 5440 Section 7.2)
struct pcep_object_header {
    uint8_t object_class;
    uint8_t ot_flags;  // OT(4bits) + Reserved(2bits) + P(1bit) + I(1bit)
    uint16_t length;
} __attribute__((packed));

// PCEP object classes
enum pcep_object_class {
    PCEP_OBJ_OPEN = 1,
    PCEP_OBJ_RP = 2,
    PCEP_OBJ_NOPATH = 3,
    PCEP_OBJ_ENDPOINTS = 4,
    PCEP_OBJ_BANDWIDTH = 5,
    PCEP_OBJ_METRIC = 6,
    PCEP_OBJ_ERO = 7,
    PCEP_OBJ_RRO = 8,
    PCEP_OBJ_LSPA = 9,
    PCEP_OBJ_IRO = 10,
    PCEP_OBJ_SVEC = 11,
    PCEP_OBJ_LSP = 32,
    PCEP_OBJ_SRP = 33,
};

// PCEP session state
enum pcep_session_state {
    PCEP_STATE_IDLE,
    PCEP_STATE_TCP_PENDING,
    PCEP_STATE_OPEN_WAIT,
    PCEP_STATE_KEEPWAIT,
    PCEP_STATE_SESSION_UP,
};

// PCEP session
struct pcep_session {
    int sockfd;
    int af_family;                      // AF_INET or AF_INET6
    union {
        struct sockaddr_in pce_addr4;   // IPv4 address
        struct sockaddr_in6 pce_addr6;  // IPv6 address
    } pce_addr;
    union {
        struct sockaddr_in local_addr4;
        struct sockaddr_in6 local_addr6;
    } local_addr;
    enum pcep_session_state state;
    uint8_t session_id;
    uint8_t keepalive_timer;
    uint8_t dead_timer;
    time_t last_activity;
    int stateful_mode;              // -1: auto, 0: disabled, 1: enabled
    bool pce_supports_stateful;     // whether the PCE supports Stateful
    pthread_mutex_t send_lock;
};

#endif /* TYPES_COMMON_H */
