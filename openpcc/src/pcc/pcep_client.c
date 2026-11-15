// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include "../../include/srv6_pcc.h"
#include "../types/common.h"
#include "pcep_client.h"
#include "../srv6/path_manager.h"

static struct pcep_session *g_session = NULL;
static pthread_t recv_thread;
static pthread_t keepalive_thread;


static void build_pcep_header(struct pcep_common_header *hdr, 
                             uint8_t msg_type, uint16_t length)
{
  // Version (3 bits) + Flags (5 bits) 
    hdr->ver_flags = (PCEP_VERSION << 5);  
    hdr->message_type = msg_type;
    hdr->message_length = htons(length);  
}

// TCP Session
static int establish_tcp_connection(struct pcep_session *session)
{
    int sockfd, ret;
    int optval = 1;
    struct sockaddr *pce_sa, *local_sa;
    socklen_t sa_len;
    
    // Socket create
    sockfd = socket(session->af_family, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    // TCP_NODELAY
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    
    // Define Struct
    if (session->af_family == AF_INET) {
        local_sa = (struct sockaddr *)&session->local_addr.local_addr4;
        pce_sa = (struct sockaddr *)&session->pce_addr.pce_addr4;
        sa_len = sizeof(struct sockaddr_in);
    } else {
        local_sa = (struct sockaddr *)&session->local_addr.local_addr6;
        pce_sa = (struct sockaddr *)&session->pce_addr.pce_addr6;
        sa_len = sizeof(struct sockaddr_in6);
    }
    
    // Bind address
    ret = bind(sockfd, local_sa, sa_len);
    if (ret < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    // Connect PCE
    ret = connect(sockfd, pce_sa, sa_len);
    if (ret < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    printf("TCP connection established to PCE (%s)\n",
           session->af_family == AF_INET ? "IPv4" : "IPv6");
    session->sockfd = sockfd;
    session->state = PCEP_STATE_TCP_PENDING;
    
    return 0;
}

// PCEP Open Message
static int send_pcep_open(struct pcep_session *session)
{
    uint8_t buf[256];
    struct pcep_common_header *hdr;
    struct pcep_object_header *obj_hdr;
    uint8_t *p;
    int msg_len, ret;
    
    memset(buf, 0, sizeof(buf));
    p = buf;
    
    // PCEP Header
    hdr = (struct pcep_common_header *)p;
    p += sizeof(struct pcep_common_header);
    
    obj_hdr = (struct pcep_object_header *)p;
    obj_hdr->object_class = PCEP_OBJ_OPEN;
    obj_hdr->ot_flags = (1 << 4); 
    
    uint8_t *obj_start = p;
    p += sizeof(struct pcep_object_header);
    
    // OPEN body (4 bytes) - RFC 5440 Section 7.3
    *p++ = (PCEP_VERSION << 5);  // Ver(3bits) | Flags(5bits)
    *p++ = session->keepalive_timer;  // Keepalive (1 byte)
    *p++ = session->dead_timer;       // DeadTimer (1 byte)
    *p++ = session->session_id;       // SID (1 byte)

    // STATEFUL-PCE-CAPABILITY TLV (RFC 8231 / RFC 8281)
    if (session->stateful_mode != 0) {
        // TLV Type = 16 (STATEFUL-PCE-CAPABILITY), Length = 4
        *p++ = 0x00;
        *p++ = 0x10;
        *p++ = 0x00;
        *p++ = 0x04;
        // Flags: U (0x01, LSP update) | I (0x04, LSP instantiation)
        *p++ = 0x00;
        *p++ = 0x00;
        *p++ = 0x00;
        *p++ = 0x05;


        // におけるpolaPCE 接続用TLV
        uint8_t extra_tlvs[] = {
            0x00, 0x22, 0x00, 0x18, 0x00, 0x00, 0x00, 0x02,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x04,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x3c, 0x00, 0x04,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x23, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00,
            0x00, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00
        };
        memcpy(p, extra_tlvs, sizeof(extra_tlvs));
        p += sizeof(extra_tlvs);

        printf("  Including STATEFUL-PCE-CAPABILITY TLV (U+I)\n");
    } else {
        printf("  Stateful capability disabled (stateless mode)\n");
    }

    uint16_t obj_len = p - obj_start;
    obj_hdr->length = htons(obj_len);
    
    msg_len = p - buf;
    build_pcep_header(hdr, PCEP_MSG_OPEN, msg_len);
    
    printf("Sending PCEP OPEN: keepalive=%d, dead=%d, session_id=%d, length=%d\n",
           session->keepalive_timer, session->dead_timer, session->session_id, msg_len);
    
    // Dump: Send Data
    printf("OPEN data: ");
    for (int i = 0; i < msg_len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
    
    ret = send(session->sockfd, buf, msg_len, 0);
    if (ret < 0) {
        perror("send OPEN");
        return -1;
    }
    
    printf("PCEP OPEN sent successfully (%d bytes)\n", ret);
    session->state = PCEP_STATE_OPEN_WAIT;
    
    return 0;
}

// Send PCEP Keepalive Message
static int send_pcep_keepalive(struct pcep_session *session)
{
    uint8_t buf[32];
    struct pcep_common_header *hdr;
    int msg_len = sizeof(struct pcep_common_header);
    int ret;
    
    hdr = (struct pcep_common_header *)buf;
    build_pcep_header(hdr, PCEP_MSG_KEEPALIVE, msg_len);
    
    pthread_mutex_lock(&session->send_lock);
    ret = send(session->sockfd, buf, msg_len, 0);
    pthread_mutex_unlock(&session->send_lock);
    
    if (ret < 0) {
        perror("send KEEPALIVE");
        return -1;
    }
    
    return 0;
}

// Recv PCEP Message
static int process_pcep_message(struct pcep_session *session, uint8_t *buf, int len)
{
    struct pcep_common_header *hdr = (struct pcep_common_header *)buf;
    
    if (len < (int)sizeof(struct pcep_common_header)) {
        fprintf(stderr, "Message too short: %d bytes\n", len);
        return -1;
    }
    
    printf("PCEP Message: version=%d, flags=0x%02x, type=%d, length=%d\n",
           hdr->ver_flags >> 5, hdr->ver_flags & 0x1F, hdr->message_type,
           ntohs(hdr->message_length));
    
    switch (hdr->message_type) {
    case PCEP_MSG_OPEN:
        printf("Received PCEP OPEN from PCE\n");
        
        // Analyze Capability
        if (len >= (int)(sizeof(struct pcep_common_header) + sizeof(struct pcep_object_header) + 4)) {
            uint8_t *obj_start = buf + sizeof(struct pcep_common_header);
            struct pcep_object_header *obj_hdr = (struct pcep_object_header *)obj_start;
            uint16_t obj_len = ntohs(obj_hdr->length);
            
            
            if (obj_len > 8) {  // object header(4) + body(4) = 8
                uint8_t *tlv_start = obj_start + 8;
                int tlv_remaining = obj_len - 8;
                
                while (tlv_remaining >= 4) {
                    uint16_t tlv_type = ntohs(*(uint16_t *)tlv_start);
                    uint16_t tlv_len = ntohs(*(uint16_t *)(tlv_start + 2));
                    
                    printf("Found TLV: Type=%d, Length=%d\n", tlv_type, tlv_len);
                    
                    if (tlv_type == 16) {  // STATEFUL-PCE-CAPABILITY
                        session->pce_supports_stateful = 1;
                        printf("PCE supports STATEFUL-PCE-CAPABILITY\n");
                        
                        if (tlv_len >= 4 && tlv_remaining >= (int)(4 + tlv_len)) {
                            uint32_t flags = ntohl(*(uint32_t *)(tlv_start + 4));
                            printf("  Flags: 0x%08x (U=%d, S=%d)\n", flags,
                                   (flags >> 31) & 1, (flags >> 30) & 1);
                        }
                    }
                    
                    
                    int tlv_total = 4 + tlv_len;
                    if (tlv_total % 4) tlv_total += 4 - (tlv_total % 4);
                    tlv_start += tlv_total;
                    tlv_remaining -= tlv_total;
                }
            }
        }
        
        // Keepalive
        send_pcep_keepalive(session);
        session->state = PCEP_STATE_KEEPWAIT;
        break;
        
    case PCEP_MSG_KEEPALIVE:
        printf("Received PCEP KEEPALIVE\n");
        session->last_activity = time(NULL);
        if (session->state == PCEP_STATE_KEEPWAIT) {
            session->state = PCEP_STATE_SESSION_UP;
            printf("PCEP session UP (waiting for PCE-initiated LSPs)\n");

            //本構成における
            uint8_t eos_pcrpt[] = {
                0x20, 0x0a, 0x00, 0x0c, // PCEP Header: ver=1, type=10(PCRpt), len=12
                0x20, 0x10, 0x00, 0x08, // LSP Object: class=32, type=1, len=8
                0x00, 0x00, 0x00, 0x00  // PLSP-ID=0, Flags=0 (End-of-Sync)
            };
            pcc_send_raw(eos_pcrpt, sizeof(eos_pcrpt));
            printf("Sent End-of-Sync PCRpt to PCE\n");
        }
        break;

    case PCEP_MSG_PCINITIATE:
        printf("Received PCEP PCInitiate (PCE-initiated LSP)\n");
        path_manager_handle_pcinitiate(buf, len);
        break;

    case PCEP_MSG_PCUPD:
        printf("Received PCEP PCUpdate\n");
        path_manager_handle_pcupdate(buf, len);
        break;

    case PCEP_MSG_PCERR:
        printf("Received PCEP ERROR\n");
        
        if (len >= (int)(sizeof(struct pcep_common_header) + sizeof(struct pcep_object_header))) {
            printf("ERROR: Check PCE logs for details\n");
        }
        return -1;
        
    case PCEP_MSG_CLOSE:
        printf("Received PCEP CLOSE from PCE\n");
        
        if (len > (int)sizeof(struct pcep_common_header)) {
            printf("PCE requested connection close\n");
        }
        return -1;
        
    default:
        printf("Unknown PCEP message type: %d\n", hdr->message_type);
        break;
    }
    
    return 0;
}

// Keepalive thread
static void *keepalive_thread_func(void *arg)
{
    struct pcep_session *session = (struct pcep_session *)arg;
    int elapsed = 0;
    int keepalive_interval;
    int dead_interval;

    keepalive_interval = session->keepalive_timer > 0 ? session->keepalive_timer : 30;
    dead_interval      = session->dead_timer      > 0 ? session->dead_timer      : 120;

    printf("Keepalive thread started (ka=%ds dead=%ds)\n",
           keepalive_interval, dead_interval);

    while (!g_shutdown) {
        sleep(1);
        elapsed++;

        if (session->state != PCEP_STATE_SESSION_UP)
            continue;

        // Send keepalive on interval
        if (elapsed >= keepalive_interval) {
            elapsed = 0;
            uint8_t kbuf[4];
            struct pcep_common_header *khdr = (struct pcep_common_header *)kbuf;
            khdr->ver_flags     = (PCEP_VERSION << 5);
            khdr->message_type  = PCEP_MSG_KEEPALIVE;
            uint16_t klen = htons(sizeof(kbuf));
            memcpy(&khdr->message_length, &klen, 2);
            pthread_mutex_lock(&session->send_lock);
            send(session->sockfd, kbuf, sizeof(kbuf), 0);
            pthread_mutex_unlock(&session->send_lock);
        }

        
        if ((int)(time(NULL) - session->last_activity) >= dead_interval) {
            fprintf(stderr, "[keepalive] Dead timer expired, disconnecting\n");
            g_shutdown = 1;
            break;
        }
    }

    printf("Keepalive thread stopped\n");
    return NULL;
}

// Recv thread
static void *recv_thread_func(void *arg)
{
    struct pcep_session *session = (struct pcep_session *)arg;
    // TCP reassembly buffer 
    uint8_t rbuf[65536];
    int     rbuf_len = 0;
    fd_set  readfds;
    struct  timeval tv;
    int     ret;

    printf("Receive thread started\n");

    while (!g_shutdown) {
        FD_ZERO(&readfds);
        FD_SET(session->sockfd, &readfds);
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        ret = select(session->sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            goto out;
        }
        if (ret == 0) continue; 

        
        int space = (int)sizeof(rbuf) - rbuf_len;
        if (space <= 0) {
            fprintf(stderr, "[recv] Reassembly buffer full, resetting\n");
            rbuf_len = 0;
            continue;
        }
        ret = recv(session->sockfd, rbuf + rbuf_len, space, 0);
        if (ret <= 0) {
            if (ret < 0) perror("recv");
            else         printf("Connection closed by peer\n");
            goto out;
        }
        session->last_activity = time(NULL);
        rbuf_len += ret;

        // Extract PCEP messages from buffer 
        while (rbuf_len >= (int)sizeof(struct pcep_common_header)) {
            struct pcep_common_header *hdr =
                (struct pcep_common_header *)rbuf;
            uint16_t msg_len;
            memcpy(&msg_len, &hdr->message_length, 2);
            msg_len = ntohs(msg_len);

            if (msg_len < (int)sizeof(struct pcep_common_header)) {
                fprintf(stderr, "[recv] Bogus msg_len=%u, resetting\n", msg_len);
                rbuf_len = 0;
                break;
            }
            if (rbuf_len < (int)msg_len) break; // wait for rest

            printf("Received %u-byte PCEP message (type=%u)\n",
                   msg_len, hdr->message_type);
            process_pcep_message(session, rbuf, msg_len);


            int rem = rbuf_len - (int)msg_len;
            if (rem > 0)
                memmove(rbuf, rbuf + msg_len, rem);
            rbuf_len = rem;
        }
    }
out:
    printf("Receive thread stopped\n");
    return NULL;
}

// Init PCC
int pcc_init(struct pcc_config *config)
{
    struct pcep_session *session;
    
    session = (struct pcep_session *)calloc(1, sizeof(struct pcep_session));
    if (!session) {
        perror("calloc");
        return -1;
    }
    
    //set af
    session->af_family = config->af_family;
    
    // set pce addr
    if (config->af_family == AF_INET) {
        session->pce_addr.pce_addr4.sin_family = AF_INET;
        session->pce_addr.pce_addr4.sin_port = htons(config->pce_port);
        if (inet_pton(AF_INET, config->pce_addr_str, 
                     &session->pce_addr.pce_addr4.sin_addr) != 1) {
            fprintf(stderr, "Invalid PCE IPv4 address\n");
            free(session);
            return -1;
        }
    } else {
        session->pce_addr.pce_addr6.sin6_family = AF_INET6;
        session->pce_addr.pce_addr6.sin6_port = htons(config->pce_port);
        if (inet_pton(AF_INET6, config->pce_addr_str,
                     &session->pce_addr.pce_addr6.sin6_addr) != 1) {
            fprintf(stderr, "Invalid PCE IPv6 address\n");
            free(session);
            return -1;
        }
    }
    
    // set local addr
    if (config->af_family == AF_INET) {
        session->local_addr.local_addr4.sin_family = AF_INET;
        session->local_addr.local_addr4.sin_port = 0; 
        if (inet_pton(AF_INET, config->local_addr_str,
                     &session->local_addr.local_addr4.sin_addr) != 1) {
            fprintf(stderr, "Invalid local IPv4 address\n");
            free(session);
            return -1;
        }
    } else {
        session->local_addr.local_addr6.sin6_family = AF_INET6;
        session->local_addr.local_addr6.sin6_port = 0; 
        if (inet_pton(AF_INET6, config->local_addr_str,
                     &session->local_addr.local_addr6.sin6_addr) != 1) {
            fprintf(stderr, "Invalid local IPv6 address\n");
            free(session);
            return -1;
        }
    }
    
    session->keepalive_timer = config->keepalive_timer;
    session->dead_timer = config->dead_timer;
    session->session_id = (uint8_t)(getpid() & 0xFF);
    session->state = PCEP_STATE_IDLE;
    session->stateful_mode = config->stateful;  
    session->pce_supports_stateful = 0;
    
    pthread_mutex_init(&session->send_lock, NULL);
    
    g_session = session;
    
    const char *stateful_str = (config->stateful == -1) ? "auto-detect" :
                               (config->stateful == 1) ? "enabled" : "disabled";
    printf("PCC initialized (%s, Stateful: %s)\n", 
           config->af_family == AF_INET ? "IPv4" : "IPv6",
           stateful_str);
    return 0;
}

// Connect PCE
int pcc_connect(void)
{
    int ret;
    
    if (!g_session) {
        fprintf(stderr, "PCC not initialized\n");
        return -1;
    }
    
    // TCP establish
    ret = establish_tcp_connection(g_session);
    if (ret < 0)
        return -1;
    
    // start recv thread
    g_shutdown = 0;
    ret = pthread_create(&recv_thread, NULL, recv_thread_func, g_session);
    if (ret != 0) {
        fprintf(stderr, "pthread_create(recv) failed: %d\n", ret);
        close(g_session->sockfd);
        return -1;
    }

    ret = pthread_create(&keepalive_thread, NULL, keepalive_thread_func, g_session);
    if (ret != 0) {
        fprintf(stderr, "pthread_create(keepalive) failed: %d\n", ret);
        g_shutdown = 1;
        pthread_join(recv_thread, NULL);
        close(g_session->sockfd);
        return -1;
    }
    
    //usleep(100000);
    
    // Send Open message
    ret = send_pcep_open(g_session);
    if (ret < 0) {
        close(g_session->sockfd);
        g_shutdown = 1;
        pthread_join(recv_thread, NULL);
        return -1;
    }
    
    return 0;
}


int pcc_send_raw(const uint8_t *buf, int len)
{
    if (!g_session || g_session->sockfd < 0) {
        fprintf(stderr, "[pcc_send_raw] No session\n");
        return -1;
    }
    pthread_mutex_lock(&g_session->send_lock);
    int ret = send(g_session->sockfd, buf, len, 0);
    pthread_mutex_unlock(&g_session->send_lock);
    return ret < 0 ? -1 : 0;
}


// clean up
int pcc_cleanup(void)
{
    if (!g_session)
        return 0;

    g_shutdown = 1;

    if (g_session->sockfd >= 0) {
        close(g_session->sockfd);
    }

    pthread_join(recv_thread, NULL);
    pthread_join(keepalive_thread, NULL);
    pthread_mutex_destroy(&g_session->send_lock);

    free(g_session);
    g_session = NULL;

    printf("PCC cleaned up\n");
    return 0;
}
