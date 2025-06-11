#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <errno.h>

#define DEVICE_PATH "/dev/advanced_firewall"
#define MAX_RULE_LENGTH 256
#define MAX_LOG_LENGTH 4096

// IOCTL commands
#define FW_ADD_RULE          _IOW('F', 1, struct firewall_rule)
#define FW_DEL_RULE          _IOW('F', 2, unsigned int)
#define FW_CLEAR_RULES       _IO('F', 3)
#define FW_GET_STATS         _IOR('F', 4, struct firewall_stats)
#define FW_RESET_STATS       _IO('F', 5)
#define FW_FLUSH_LOG         _IO('F', 6)

// Rule directions
#define DIR_IN       0
#define DIR_OUT      1
#define DIR_FORWARD  2

// Rule actions
#define RULE_ACCEPT  0
#define RULE_DROP    1
#define RULE_REJECT  2
#define RULE_LOG     3

// Protocol types
#define PROTO_ALL    0
#define PROTO_TCP    1
#define PROTO_UDP    2
#define PROTO_ICMP   3

// Rule flags
#define FLAG_ESTABLISHED 0x01
#define FLAG_NEW        0x02
#define FLAG_INVALID    0x04
#define FLAG_RELATED    0x08

// Firewall rule structure (must match kernel module)
struct firewall_rule {
    unsigned int id;
    unsigned char action;
    unsigned char direction;
    unsigned char protocol;
    unsigned int src_ip;
    unsigned int src_mask;
    unsigned int dst_ip;
    unsigned int dst_mask;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char flags;
    unsigned int rate_limit;
    char iface_in[16];
    char iface_out[16];
};

// Firewall statistics structure (must match kernel module)
struct firewall_stats {
    unsigned long long packets_total;
    unsigned long long packets_accepted;
    unsigned long long packets_dropped;
    unsigned long long bytes_total;
    unsigned long long bytes_accepted;
    unsigned long long bytes_dropped;
    unsigned long long conn_count;
    unsigned long long new_conn_count;
};

void print_help() {
    printf("Advanced Firewall Control Utility\n");
    printf("Usage:\n");
    printf("  firewallctl [options] [arguments]\n\n");
    printf("Options:\n");
    printf("  -a, --add-rule      Add a new firewall rule\n");
    printf("  -d, --delete-rule   Delete a rule by ID\n");
    printf("  -c, --clear-rules   Clear all firewall rules\n");
    printf("  -s, --show-stats    Show firewall statistics\n");
    printf("  -r, --reset-stats   Reset firewall statistics\n");
    printf("  -l, --show-log      Show firewall log\n");
    printf("  -f, --flush-log     Flush firewall log\n");
    printf("  -h, --help          Show this help message\n\n");
    printf("Rule format for --add-rule:\n");
    printf("  direction=in|out|forward action=accept|drop|reject|log\n");
    printf("  protocol=all|tcp|udp|icmp src_ip=IP[/mask] dst_ip=IP[/mask]\n");
    printf("  src_port=PORT dst_port=PORT flags=established|new|related|invalid\n");
    printf("  rate_limit=N iface_in=IFACE iface_out=IFACE\n\n");
    printf("Examples:\n");
    printf("  firewallctl -a \"direction=in action=drop protocol=tcp dst_port=80\"\n");
    printf("  firewallctl -d 42\n");
    printf("  firewallctl -s\n");
}

int parse_ip_mask(const char *str, unsigned int *ip, unsigned int *mask) {
    char *slash = strchr(str, '/');
    char ip_str[16];
    
    if (slash) {
        strncpy(ip_str, str, slash - str);
        ip_str[slash - str] = '\0';
        *mask = atoi(slash + 1);
        if (*mask > 32) return -1;
        *mask = htonl(~((1 << (32 - *mask)) - 1));
    } else {
        strcpy(ip_str, str);
        *mask = 0xFFFFFFFF;
    }
    
    if (inet_pton(AF_INET, ip_str, ip) != 1) {
        return -1;
    }
    
    *ip = ntohl(*ip);
    return 0;
}

int parse_rule(const char *rule_str, struct firewall_rule *rule) {
    char *token, *rest;
    char *copy = strdup(rule_str);
    
    memset(rule, 0, sizeof(struct firewall_rule));
    rule->src_mask = 0xFFFFFFFF;
    rule->dst_mask = 0xFFFFFFFF;
    
    rest = copy;
    while ((token = strsep(&rest, " ")) != NULL) {
        char *key = strsep(&token, "=");
        char *value = token;
        
        if (!key || !value) continue;
        
        if (strcmp(key, "direction") == 0) {
            if (strcmp(value, "in") == 0) rule->direction = DIR_IN;
            else if (strcmp(value, "out") == 0) rule->direction = DIR_OUT;
            else if (strcmp(value, "forward") == 0) rule->direction = DIR_FORWARD;
            else return -1;
        }
        else if (strcmp(key, "action") == 0) {
            if (strcmp(value, "accept") == 0) rule->action = RULE_ACCEPT;
            else if (strcmp(value, "drop") == 0) rule->action = RULE_DROP;
            else if (strcmp(value, "reject") == 0) rule->action = RULE_REJECT;
            else if (strcmp(value, "log") == 0) rule->action = RULE_LOG;
            else return -1;
        }
        else if (strcmp(key, "protocol") == 0) {
            if (strcmp(value, "all") == 0) rule->protocol = PROTO_ALL;
            else if (strcmp(value, "tcp") == 0) rule->protocol = PROTO_TCP;
            else if (strcmp(value, "udp") == 0) rule->protocol = PROTO_UDP;
            else if (strcmp(value, "icmp") == 0) rule->protocol = PROTO_ICMP;
            else return -1;
        }
        else if (strcmp(key, "src_ip") == 0) {
            if (parse_ip_mask(value, &rule->src_ip, &rule->src_mask) != 0) return -1;
        }
        else if (strcmp(key, "dst_ip") == 0) {
            if (parse_ip_mask(value, &rule->dst_ip, &rule->dst_mask) != 0) return -1;
        }
        else if (strcmp(key, "src_port") == 0) {
            rule->src_port = htons(atoi(value));
        }
        else if (strcmp(key, "dst_port") == 0) {
            rule->dst_port = htons(atoi(value));
        }
        else if (strcmp(key, "flags") == 0) {
            char *flag;
            while ((flag = strsep(&value, ",")) != NULL) {
                if (strcmp(flag, "established") == 0) rule->flags |= FLAG_ESTABLISHED;
                else if (strcmp(flag, "new") == 0) rule->flags |= FLAG_NEW;
                else if (strcmp(flag, "related") == 0) rule->flags |= FLAG_RELATED;
                else if (strcmp(flag, "invalid") == 0) rule->flags |= FLAG_INVALID;
                else return -1;
            }
        }
        else if (strcmp(key, "rate_limit") == 0) {
            rule->rate_limit = atoi(value);
        }
        else if (strcmp(key, "iface_in") == 0) {
            strncpy(rule->iface_in, value, sizeof(rule->iface_in) - 1);
        }
        else if (strcmp(key, "iface_out") == 0) {
            strncpy(rule->iface_out, value, sizeof(rule->iface_out) - 1);
        }
    }
    
    free(copy);
    return 0;
}

void print_stats(const struct firewall_stats *stats) {
    printf("Firewall Statistics:\n");
    printf("  Total packets: %llu\n", stats->packets_total);
    printf("  Accepted packets: %llu\n", stats->packets_accepted);
    printf("  Dropped packets: %llu\n", stats->packets_dropped);
    printf("  Total bytes: %llu\n", stats->bytes_total);
    printf("  Accepted bytes: %llu\n", stats->bytes_accepted);
    printf("  Dropped bytes: %llu\n", stats->bytes_dropped);
    printf("  Active connections: %llu\n", stats->conn_count);
    printf("  New connections: %llu\n", stats->new_conn_count);
}

int show_log(int fd) {
    char log_buffer[MAX_LOG_LENGTH];
    ssize_t bytes_read;
    
    lseek(fd, 0, SEEK_SET);
    bytes_read = read(fd, log_buffer, sizeof(log_buffer) - 1);
    if (bytes_read < 0) {
        perror("Failed to read log");
        return -1;
    }
    
    log_buffer[bytes_read] = '\0';
    printf("Firewall Log:\n%s", log_buffer);
    return 0;
}

int main(int argc, char *argv[]) {
    int fd;
    int ret = 0;
    
    if (argc < 2) {
        print_help();
        return 0;
    }
    
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    
    if (strcmp(argv[1], "-a") == 0 || strcmp(argv[1], "--add-rule") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Rule specification required\n");
            print_help();
            ret = 1;
            goto out;
        }
        
        struct firewall_rule rule;
        if (parse_rule(argv[2], &rule) {
            fprintf(stderr, "Error: Invalid rule format\n");
            print_help();
            ret = 1;
            goto out;
        }
        
        if (ioctl(fd, FW_ADD_RULE, &rule) < 0) {
            perror("Failed to add rule");
            ret = 1;
            goto out;
        }
        
        printf("Rule added successfully with ID: %u\n", rule.id);
    }
    else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--delete-rule") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Rule ID required\n");
            print_help();
            ret = 1;
            goto out;
        }
        
        unsigned int rule_id = atoi(argv[2]);
        if (ioctl(fd, FW_DEL_RULE, &rule_id) < 0) {
            perror("Failed to delete rule");
            ret = 1;
            goto out;
        }
        
        printf("Rule %u deleted successfully\n", rule_id);
    }
    else if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--clear-rules") == 0) {
        if (ioctl(fd, FW_CLEAR_RULES) < 0) {
            perror("Failed to clear rules");
            ret = 1;
            goto out;
        }
        
        printf("All rules cleared successfully\n");
    }
    else if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--show-stats") == 0) {
        struct firewall_stats stats;
        if (ioctl(fd, FW_GET_STATS, &stats) < 0) {
            perror("Failed to get stats");
            ret = 1;
            goto out;
        }
        
        print_stats(&stats);
    }
    else if (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "--reset-stats") == 0) {
        if (ioctl(fd, FW_RESET_STATS) < 0) {
            perror("Failed to reset stats");
            ret = 1;
            goto out;
        }
        
        printf("Statistics reset successfully\n");
    }
    else if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--show-log") == 0) {
        if (show_log(fd) < 0) {
            ret = 1;
            goto out;
        }
    }
    else if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--flush-log") == 0) {
        if (ioctl(fd, FW_FLUSH_LOG) < 0) {
            perror("Failed to flush log");
            ret = 1;
            goto out;
        }
        
        printf("Log flushed successfully\n");
    }
    else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_help();
    }
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
        print_help();
        ret = 1;
    }

out:
    close(fd);
    return ret;
}