#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define APP_PORT 8080
#define LOGGER_IP "10.0.0.4"
#define LOGGER_PORT 9999
#define BUFFER_SIZE 1024

// Forward security incident to Centralized Logger
void notify_security_logger(const char *client_ip, const char *reason) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in logger_addr;
    memset(&logger_addr, 0, sizeof(logger_addr));
    logger_addr.sin_family = AF_INET;
    logger_addr.sin_port = htons(LOGGER_PORT);
    inet_pton(AF_INET, LOGGER_IP, &logger_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&logger_addr, sizeof(logger_addr)) == 0) {
        char report[BUFFER_SIZE];
        snprintf(report, sizeof(report), "ALERT: IP=%s REASON=%s ACTION=SDN_FLOW_DROP", client_ip, reason);
        send(sock, report, strlen(report), 0);
    }
    close(sock);
}

// Dynamically install OpenFlow drop rule with 30-second automatic recovery on switch s1
void trigger_sdn_block(const char *client_ip) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "sudo ovs-ofctl add-flow s1 \"priority=50000,hard_timeout=30,ip,nw_src=%s,actions=drop\" > /dev/null 2>&1 &",
        client_ip);
    system(cmd);
}





struct ClientInfo {
    int socket;
    struct sockaddr_in addr;
};

void *handle_client(void *arg) {
    struct ClientInfo *ci = (struct ClientInfo *)arg;
    int client_sock = ci->socket;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ci->addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    free(ci);

    char buffer[BUFFER_SIZE];    memset(buffer, 0, sizeof(buffer));

    ssize_t bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        printf("[APP SERVER] Received from %s: %s\n", client_ip, buffer);

        // Security check: inspect payload for malicious keywords
        if (strstr(buffer, "ATTACK") != NULL || strstr(buffer, "MALICIOUS") != NULL || strstr(buffer, "EXPLOIT") != NULL) {
            printf("[APP SERVER] Security violation from %s! Triggering Firewall & Logging...\n", client_ip);
            notify_security_logger(client_ip, "UNAUTHORIZED_PAYLOAD_DETECTED");
            trigger_sdn_block(client_ip);

            const char *denied = "403 FORBIDDEN: Blocked by Dynamic SDN Firewall\n";
            send(client_sock, denied, strlen(denied), 0);
        } else {
            // Normal response
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), "200 OK: Processed request: %s\n", buffer);
            send(client_sock, response, strlen(response), 0);
        }
    }

    close(client_sock);
    return NULL;
}

int main() {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(APP_PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 20) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("[APP SERVER] Listening on port %d...\n", APP_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock < 0) continue;

        struct ClientInfo *ci = malloc(sizeof(struct ClientInfo));
        ci->socket = client_sock;
        ci->addr = client_addr;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, ci);
        pthread_detach(tid);
    }

    close(server_sock);
    return 0;
}
