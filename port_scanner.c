/*
 * port_scanner.c — TCP Connect Port Scanner
 * Author: Krishna Aggarwal
 *
 * A TCP Connect port scanner that establishes full three-way handshakes
 * to identify open ports on a target host. Uses non-blocking sockets
 * with select() for timeout control.
 *
 * ⚠ WARNING: Use ONLY on systems you own or have explicit written
 *   permission to scan. Unauthorized port scanning may be illegal.
 *
 * Concepts demonstrated:
 *   - TCP three-way handshake mechanics (SYN → SYN/ACK → ACK)
 *   - Non-blocking socket I/O (O_NONBLOCK + select())
 *   - Network enumeration fundamentals
 *   - Service identification by well-known port numbers
 *
 * Compile: gcc -o port_scanner port_scanner.c
 * Usage:   ./port_scanner <target_ip> <start_port> <end_port>
 * Example: ./port_scanner 127.0.0.1 1 1024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

#define TIMEOUT_SEC  1
#define TIMEOUT_USEC 0

/* Well-known port to service name mapping */
typedef struct {
    int port;
    const char *service;
} PortService;

static const PortService known_services[] = {
    {21,   "FTP"},
    {22,   "SSH"},
    {23,   "Telnet"},
    {25,   "SMTP"},
    {53,   "DNS"},
    {80,   "HTTP"},
    {110,  "POP3"},
    {143,  "IMAP"},
    {443,  "HTTPS"},
    {445,  "SMB"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {5432, "PostgreSQL"},
    {6379, "Redis"},
    {8080, "HTTP-Alt"},
    {8443, "HTTPS-Alt"},
    {0,    NULL}
};

const char *identify_service(int port) {
    for (int i = 0; known_services[i].service != NULL; i++) {
        if (known_services[i].port == port)
            return known_services[i].service;
    }
    return "Unknown";
}

/*
 * Attempts a TCP connect to target:port.
 * Returns 1 if port is open, 0 if closed/filtered, -1 on error.
 *
 * Uses non-blocking connect + select() so a single slow/filtered port
 * does not stall the entire scan. TIMEOUT_SEC controls max wait per port.
 */
int scan_port(const char *ip, int port) {
    int sock;
    struct sockaddr_in addr;
    fd_set write_fds;
    struct timeval tv;
    int result;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    /* Set socket non-blocking */
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    if (result == 0) {
        /* Immediate connection (rare but possible for localhost) */
        close(sock);
        return 1;
    }

    if (errno != EINPROGRESS) {
        /* Immediate refusal */
        close(sock);
        return 0;
    }

    /* Wait for connect() to complete or timeout */
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    tv.tv_sec  = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_USEC;

    result = select(sock + 1, NULL, &write_fds, NULL, &tv);

    if (result > 0 && FD_ISSET(sock, &write_fds)) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        close(sock);
        return (so_error == 0) ? 1 : 0;
    }

    /* Timeout or error */
    close(sock);
    return 0;
}

void print_separator(void) {
    printf("─────────────────────────────────────────────────\n");
}

int main(int argc, char *argv[]) {
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║      TCP Connect Port Scanner                 ║\n");
    printf("║      Author: Krishna Aggarwal                 ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    printf("⚠  AUTHORIZED USE ONLY. Scanning systems without\n");
    printf("   permission may be illegal under IT Act, 2000.\n\n");

    if (argc != 4) {
        printf("Usage:   %s <target_ip> <start_port> <end_port>\n", argv[0]);
        printf("Example: %s 127.0.0.1 1 1024\n\n", argv[0]);
        printf("Scans TCP ports in range [start_port, end_port] on target_ip.\n");
        printf("Uses non-blocking sockets with %ds timeout per port.\n", TIMEOUT_SEC);
        return 1;
    }

    char *target    = argv[1];
    int   start     = atoi(argv[2]);
    int   end_port  = atoi(argv[3]);

    if (start < 1 || end_port > 65535 || start > end_port) {
        fprintf(stderr, "Error: Port range must be 1–65535 with start ≤ end.\n");
        return 1;
    }

    printf("Target  : %s\n", target);
    printf("Range   : %d – %d (%d ports)\n", start, end_port, end_port - start + 1);
    printf("Timeout : %d second(s) per port\n", TIMEOUT_SEC);
    print_separator();

    int open_count   = 0;
    int closed_count = 0;

    for (int port = start; port <= end_port; port++) {
        int status = scan_port(target, port);
        if (status == 1) {
            printf("[OPEN]   %-6d  %s\n", port, identify_service(port));
            open_count++;
        } else {
            closed_count++;
        }
    }

    print_separator();
    printf("Scan complete.\n");
    printf("Total : %d  |  Open : %d  |  Closed/Filtered : %d\n",
           end_port - start + 1, open_count, closed_count);

    return 0;
}
