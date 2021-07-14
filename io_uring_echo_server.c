#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "liburing.h"

#define MAX_CONNECTIONS     512
#define BACKLOG             512
#define MAX_MESSAGE_LEN     1024
#define BUFFERS_COUNT       MAX_CONNECTIONS


void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags);
void add_socket_read(struct io_uring *ring, int fd, size_t size, unsigned flags);
void add_socket_write(struct io_uring *ring, int fd, size_t size, unsigned flags);

int register_files(struct io_uring *ring);
int register_buffers(struct io_uring *ring);


/*
REMOVED BUFFER SELECTION

void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t size, unsigned flags);
void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t size, unsigned flags);
void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid);
*/

enum {
    ACCEPT,
    READ,
    WRITE,
    PROV_BUF,
};

typedef struct conn_info {
    __u32 fd;
    __u16 type;
    __u16 bid;
} conn_info;

struct iovec iov[MAX_CONNECTIONS];
char bufs[MAX_CONNECTIONS][MAX_MESSAGE_LEN] = {0};

int registered_files[MAX_CONNECTIONS];
int files[MAX_CONNECTIONS];

int group_id = 1337;

int main(int argc, char *argv[]) {
 
    printf("IO_URING ECHO SERVER - v2\n");
    printf("Features: \n");
    printf("Automatic Buffer Selection - NO \n");
    printf("File Set Registration - YES \n");
    printf("Fixed Buffers - YES \n");
    printf("Read_Fixed/Write_Fixed - NO \n");
    printf("Recv_Fixed/Send_Fixed - NO \n");

    if (argc < 2) 
    {
        printf("Please give a port number: ./io_uring_echo_server [port]\n");
        exit(0);
    }

    // some variables we need
    int portno = strtol(argv[1], NULL, 10);
    struct sockaddr_in serv_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // setup socket
    int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    const int val = 1;
    setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // bind and listen
    if (bind(sock_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        perror("Error binding socket...\n");
        exit(1);
    }
    if (listen(sock_listen_fd, BACKLOG) < 0) 
    {
        perror("Error listening on socket...\n");
        exit(1);
    }
    printf("io_uring echo server listening for connections on port: %d\n", portno);

    // initialize io_uring
    struct io_uring_params params;
    struct io_uring ring;
    memset(&params, 0, sizeof(params));

    if (io_uring_queue_init_params(2048, &ring, &params) < 0) 
    {
        perror("io_uring_init_params failed...\n");
        exit(1); 
    }

    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) 
    {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }

    if (register_files(&ring) < 0)
    {
        perror("io_uring_register_files failed...\n");
        exit(1); 
    }       
    if (io_uring_register_files_update(&ring, sock_listen_fd, &sock_listen_fd, 1) < 0)
    {
        perror("io_uring_register_files_update for sock_listen failed...\n");
        exit(1);
	}
	registered_files[sock_listen_fd] = sock_listen_fd;    

    if (register_buffers(&ring) < 0)
    {
        perror("io_uring_register_buffers failed...\n");
        exit(1); 
    }  

    /* 
    REMOVED PROVIDE_BUFFER CALLS TO REMOVE BUFFER SELECTION

    // // check if buffer selection is supported
    // struct io_uring_probe *probe;
    // probe = io_uring_get_probe_ring(&ring);
    // if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
    //     printf("Buffer select not supported, skipping...\n");
    //     exit(0);
    // }
    // free(probe);

    // register buffers for buffer selection
    // struct io_uring_sqe *sqe;
    // struct io_uring_cqe *cqe;

    // sqe = io_uring_get_sqe(&ring);
    // io_uring_prep_provide_buffers(sqe, bufs, MAX_MESSAGE_LEN, BUFFERS_COUNT, group_id, 0);

    // io_uring_submit(&ring);
    // io_uring_wait_cqe(&ring, &cqe);
    // if (cqe->res < 0) {
    //     printf("cqe->res = %d\n", cqe->res);
    //     exit(1);
    // }
    // io_uring_cqe_seen(&ring, cqe);

    */

    // add first accept SQE to monitor for new incoming connections
    add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, 0);

    // start event loop
    while (1) 
    {
        io_uring_submit_and_wait(&ring, 1);
        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned count = 0;

        // go through all CQEs
        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            struct conn_info conn_i;
            memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));

            int type = conn_i.type;
            
            /*
            REMOVED AUTOMATIC BUFFER  HANDLING WHILE PROCESSING CQEs

            // if (cqe->res == -ENOBUFS) {
            //     fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen...\n");
            //     fflush(stdout);
            //     exit(1);
            // } else if (type == PROV_BUF) {
            //     if (cqe->res < 0) {
            //         printf("cqe->res = %d\n", cqe->res);
            //         exit(1);
            //     }
            // } else

            */

            if (type == ACCEPT) 
            {
                int sock_conn_fd = cqe->res;
                // only read when there is no error, >= 0
                if (sock_conn_fd >= 0) 
                {
                    if (registered_files[sock_conn_fd] == -1)
                    {
                        if (io_uring_register_files_update(&ring, sock_conn_fd, &sock_conn_fd, 1) < 0)
                        {
                            perror("io_uring_register_files_update for sock_listen failed...\n");
                            exit(1);
                        }
                        registered_files[sock_conn_fd] = sock_conn_fd;    
                    }

                    /*
                    REMOVED BUFFER SELECTION CALL
                    add_socket_read(&ring, sock_conn_fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
                    */
                    add_socket_read(&ring, sock_conn_fd, MAX_MESSAGE_LEN, 0);
                }

                // new connected client; read data from socket and re-add accept to monitor for new connections
                int flags = IOSQE_FIXED_FILE;
                add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, flags);
            } 
            else if (type == READ) 
            {
                int bytes_read = cqe->res;
                /*
                //REMOVED BUFFER SELECTION CALL
                int bid = cqe->flags >> 16;
                */
                if (cqe->res <= 0) 
                {
                    /*
                    REMOVED BUFFER SELECTION CALL
                    // read failed, re-add the buffer
                    add_provide_buf(&ring, bid, group_id);
                    */

                    // connection closed or error
                    shutdown(conn_i.fd, SHUT_RDWR);
                } 
                else 
                {
                    /*
                    REMOVED BUFFER SELECTION CALL
                    // bytes have been read into bufs, now add write to socket sqe
                    add_socket_write(&ring, conn_i.fd, bid, bytes_read, 0);
                    */

                    // bytes have been read into bufs, now add write to socket sqe
                    int flags = IOSQE_FIXED_FILE;
                    add_socket_write(&ring, conn_i.fd, bytes_read, flags);
                }
            } 
            else if (type == WRITE) 
            {
                /*
                REMOVED BUFFER SELECTION CALL

                // write has been completed, first re-add the buffer
                add_provide_buf(&ring, conn_i.bid, group_id);
                // add a new read for the existing connection
                add_socket_read(&ring, conn_i.fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
                */

                // add a new read for the existing connection
                int flags = IOSQE_FIXED_FILE;
                add_socket_read(&ring, conn_i.fd, MAX_MESSAGE_LEN, flags);
            }
        }

        io_uring_cq_advance(&ring, count);
    }
}

int register_files(struct io_uring *ring) 
{
    for (int i = 0; i < MAX_CONNECTIONS; i++)
		files[i] = -1;

	for (int i = 0; i < MAX_CONNECTIONS; i++)
		registered_files[i] = -1;

	return io_uring_register_files(ring, files, MAX_CONNECTIONS);
}

int register_buffers(struct io_uring *ring) 
{
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        iov[i].iov_base = &bufs[i];
        iov[i].iov_len = MAX_MESSAGE_LEN;
        memset(iov[i].iov_base, 0, iov[i].iov_len);
    }

	//return io_uring_register_buffers(ring, iov, MAX_CONNECTIONS);
    return 0;
}

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags) 
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, fd, client_addr, client_len, 0);
    io_uring_sqe_set_flags(sqe, flags);

    conn_info conn_i = 
    {
        .fd = fd,
        .type = ACCEPT,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

/*

REMOVED ARGUMENTS FOR BUFFER SELECTION
//void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags) {

*/
void add_socket_read(struct io_uring *ring, int fd, size_t message_size, unsigned flags) 
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    /*
    REMOVED BUFFER SELECTION 
    io_uring_prep_recv(sqe, fd, NULL, message_size, 0);
    sqe->buf_group = gid;
    */
    io_uring_prep_recv(sqe, fd, iov[fd].iov_base, message_size, 0);
    io_uring_sqe_set_flags(sqe, flags);

    conn_info conn_i = 
    {
        .fd = fd,
        .type = READ,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

/*

TODO REMOVE CALLS FOR BUFFER SELECTION
//void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t message_size, unsigned flags) {

*/
void add_socket_write(struct io_uring *ring, int fd, size_t message_size, unsigned flags) 
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    /*
    REMOVED BUFFER SELECTION 
    io_uring_prep_send(sqe, fd, &bufs[bid], message_size, 0);'
    conn_info conn_i = 
    {
        .fd = fd,
        .type = WRITE,
        .bid = bid,
    };
    */
    io_uring_prep_send(sqe, fd, iov[fd].iov_base, message_size, 0);
    io_uring_sqe_set_flags(sqe, flags);

    conn_info conn_i = 
    {
        .fd = fd,
        .type = WRITE,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

/*
REMOVED ADD_PROVIDE_BUFFER CALL TO REMOVE BUFFER SELECTION

// void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
//     io_uring_prep_provide_buffers(sqe, bufs[bid], MAX_MESSAGE_LEN, 1, gid, bid);

//     conn_info conn_i = {
//         .fd = 0,
//         .type = PROV_BUF,
//     };
//     memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
// }

*/