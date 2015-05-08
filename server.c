#define _BSD_SOURCE
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>



int passivesock(char* service, char* protocol, int qlen )
{
    struct servent *pse; /* pointer to service information entry */
    struct protoent *ppe; /* pointer to protocol information entry*/
    struct sockaddr_in sin; /* an Internet endpoint address */
    int s, type, portbase = 0; /* socket descriptor and socket type */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    /* Map service name to port number */
    if ( pse = getservbyname(service, protocol) )
        sin.sin_port = htons(ntohs((unsigned short)pse->s_port) + portbase);
    else if ( (sin.sin_port = htons((unsigned short)atoi(service))) == 0 )
    {
        printf("can't get \"%s\" service entry\n", service);
        return -1;
    }
    /* Map protocol name to protocol number */
    if ( (ppe = getprotobyname(protocol)) == 0)
    {
        printf("can't get \"%s\" protocol entry\n", protocol);
        return -1;
    }
    /* Use protocol to choose a socket type */
    if (strcmp(protocol, "udp") == 0)
        type = SOCK_DGRAM;
    else
        type = SOCK_STREAM;
    /* Allocate a socket */
    s = socket(PF_INET, type, ppe->p_proto);
    if (s < 0)
    {
        printf("can't create socket\n");
        return -1;
    }
    /* Bind the socket */
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        printf("can't bind to %s port\n", service);
        return -1;
    }
    if (type == SOCK_STREAM && listen(s, qlen) < 0)
    {
        printf("can't listen on %s port\n", service);
        return -1;
    }
    return s;
}

int passiveTCP(char* service, int qlen )
{
    return passivesock(service, "tcp", qlen);
}

void recv_file(int sock)
{
    int recv_size;
    FILE *fp;
    char filename[1000], inbuf;
    pid_t pid;
    pid = getpid();
    snprintf(filename, 1000, "scan_%d", pid);
    fp = fopen(filename, "wb");
    while((recv_size=read(sock, &inbuf, 1))>0)
    {
        fputc(inbuf, fp);
        if(inbuf == '\0')
            break;
    }
    fclose(fp);

}

int main (int argc, char* argv)
{
    int psock, csock, clilen, childpid;
    struct sockaddr_in cli_addr, serv_addr;

    psock = passiveTCP("7000", 5);
    if(psock<0)
        printf("ERROR : create socket error\n");
    else
    {

        while(true)
        {
            clilen = sizeof(cli_addr);
            csock = accept(psock, (struct sockaddr *) &cli_addr, &clilen);
            if (csock < 0) 
                printf("server: accept error\n");
            else if ( (childpid = fork()) < 0)
                printf("server: fork error\n");
            else if (childpid == 0)
            { /* child process */
                /* close original socket */
                close(psock);
                /* process the request */
                char popen_filename[2000];
                FILE *clam_fp;

                recv_file(csock);
                snprintf(popen_filename, 2000, "/usr/bin/clamscan -i scan_%d", getpid());
                clam_fp = popen(popen_filename, "r");
                if(fgetc(clam_fp) == 10)
                    send(csock, "safe", 4, 0);
                else
                    send(csock, "danger", 6, 0);
                snprintf(popen_filename, 2000, "/bin/rm scan_%d", getpid());

                exit(0);//close child process
            }
            printf("cpid = %d\n", childpid);
            close(csock); /* parent process */
        }
    }
}