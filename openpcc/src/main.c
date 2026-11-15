// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include "../include/srv6_pcc.h"
#include "srv6/path_manager.h"


volatile sig_atomic_t g_shutdown = 0;

void signal_handler(int signum)
{
    printf("\nReceived signal %d, shutting down...\n", signum);
    g_shutdown = 1;
}

void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -p <PCE address>     PCE address (IPv4 or IPv6, auto-detected)\n");
    printf("  -P <port>            PCE port (default: 4189)\n");
    printf("  -l <local address>   Local address (must match PCE address family)\n");
    printf("  -k <seconds>         Keepalive timer (default: 30)\n");
    printf("  -d <seconds>         Dead timer (default: 120)\n");
    printf("  -s                   Enable Stateful PCE capabilities (default: auto-detect)\n");
    printf("  -S                   Disable Stateful PCE capabilities\n");
    printf("  -i <interface>       Output interface for installed local SIDs\n");
    printf("  -b <bits>            uSID locator-block length in bits (default: 32)\n");
    printf("  -n <bits>            uSID node-function length in bits (default: 16)\n");
    printf("  -h                   Show this help\n");
    printf("\nExamples:\n");
    printf("  IPv6: %s -p fc00::1 -l fc00::2 -i eth0\n", prog);
    printf("  IPv4: %s -p 192.168.1.1 -l 192.168.1.2\n", prog);
}

int main(int argc, char *argv[])
{
    struct pcc_config config = {
        .pce_addr_str = "",
        .pce_port = PCEP_DEFAULT_PORT,
        .local_addr_str = "",
        .keepalive_timer = 30,
        .dead_timer = 120,
        .stateful = -1,  
        .config_file = NULL,
        .af_family = AF_INET6,  
    };
    int opt, ret;
    struct in6_addr test_addr6;
    struct in_addr test_addr4;
    const char *oif_name = NULL;
    int lcblock_bits = 0;   
    int lcnode_bits  = 0;   


    while ((opt = getopt(argc, argv, "p:P:l:k:d:i:b:n:sSh")) != -1) {
        switch (opt) {
        case 'p':
            strncpy(config.pce_addr_str, optarg, sizeof(config.pce_addr_str) - 1);
            // IPv6
            if (inet_pton(AF_INET6, config.pce_addr_str, &test_addr6) == 1) {
                config.af_family = AF_INET6;
            }
            // IPv4
            else if (inet_pton(AF_INET, config.pce_addr_str, &test_addr4) == 1) {
                config.af_family = AF_INET;
            }
            else {
                fprintf(stderr, "Invalid PCE address: %s\n", config.pce_addr_str);
                return 1;
            }
            break;
        case 'P':
            config.pce_port = atoi(optarg);
            break;
        case 'l':
            strncpy(config.local_addr_str, optarg, sizeof(config.local_addr_str) - 1);
            
            if (config.af_family == AF_INET6) {
                if (inet_pton(AF_INET6, config.local_addr_str, &test_addr6) != 1) {
                    fprintf(stderr, "Local address must be IPv6 (PCE is IPv6): %s\n", 
                           config.local_addr_str);
                    return 1;
                }
            } else {
                if (inet_pton(AF_INET, config.local_addr_str, &test_addr4) != 1) {
                    fprintf(stderr, "Local address must be IPv4 (PCE is IPv4): %s\n",
                           config.local_addr_str);
                    return 1;
                }
            }
            break;
        case 'k':
            config.keepalive_timer = atoi(optarg);
            break;
        case 'd':
            config.dead_timer = atoi(optarg);
            break;
        case 'i':
            oif_name = optarg;
            break;
        case 'b':
            lcblock_bits = atoi(optarg);
            break;
        case 'n':
            lcnode_bits = atoi(optarg);
            break;
        case 's':
            config.stateful = 1;
            break;
        case 'S':
            config.stateful = 0;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (config.pce_addr_str[0] == '\0' || config.local_addr_str[0] == '\0') {
        fprintf(stderr, "PCE address (-p) and local address (-l) are required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    printf("OpenPCC - SRv6 stateful PCC v%s\n", SRV6_PCC_VERSION);
    printf("Address Family: %s\n", config.af_family == AF_INET ? "IPv4" : "IPv6");
    printf("PCE: %s:%u\n", config.pce_addr_str, config.pce_port);
    printf("Local: %s\n", config.local_addr_str);
    printf("Stateful PCE: %s\n", 
           config.stateful == -1 ? "auto-detect" :
           config.stateful == 1 ? "enabled" : "disabled");
    

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    

    path_manager_init(oif_name, lcblock_bits, lcnode_bits);


    ret = pcc_init(&config);
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize PCC\n");
        return 1;
    }


    ret = pcc_connect();
    if (ret < 0) {
        fprintf(stderr, "Failed to connect to PCE\n");
        pcc_cleanup();
        return 1;
    }

    printf("Connected to PCE, waiting for PCE-initiated SRv6 LSPs...\n");


    while (!g_shutdown) {
        sleep(1);
    }
    

    pcc_cleanup();
    
    printf("PCC shutdown complete\n");
    return 0;
}
