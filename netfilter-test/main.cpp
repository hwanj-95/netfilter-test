#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "header.h"
#include <linux/in.h>
#include <string.h>

#define host 8
char* HostAddr; // argv
int host_size; // argv len
static int check;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

int Url_filter(unsigned char* data){
    struct Ip_hdr* IP = (struct Ip_hdr*)data;
    int ip_hdr_len = (IP->ip_hl)*4;
    int total_len = ntohs(IP->ip_len);
    data = data + ip_hdr_len;
    struct Tcp_hdr* TCP = (struct Tcp_hdr*)data;
    int tcp_hdr_len = (TCP->th_off)*4;
    int tcp_payload = total_len - ip_hdr_len - tcp_hdr_len;
    data = data + tcp_hdr_len;
    char data_buf[host_size]; // data_copy
    char host_buf[host_size]; // Input_copy
    if(IP->ip_p == IPPROTO_TCP && ntohs(TCP->th_dport) == 80){
        for(int i = 0; i<tcp_payload; i++ ){
            if(data[i] == 0x0d && data[i+1] == 0x0a && data[i+2] == 0x48 && data[i+3] == 0x6f &&
               data[i+4] == 0x73 && data[i+5] == 0x74 && data[i+6] == 0x3a && data[i+7] == 0x20){
                printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
                printf("host addr size : %d\n", host_size);

                for(int j=0; j<host_size; j++){
                    data_buf[j] = data[i+host+j];
                }

                printf("Input URL : %s\n",data_buf);

                strcpy(host_buf, HostAddr); // copy

                printf("Block URL : %s\n", host_buf);

                printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
                return check = strcmp(host_buf, data_buf);

            }
        }
    }return check = 99;

    return 0;
}



/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u \n", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);

    Url_filter(data);
    //dump(data, ret);
    printf("\n");
    if (ret >= 0){
        printf("payload_len=%d \n", ret);
    }

    printf(" print  $$$$ check : %d\n", check);
    printf("\n\n----------------------------------------------------------------------\n\n");
    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    if(check == 0){
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }else{
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

}

void usage() {
    printf("syntax : netfilter-test <host>");
    printf("sample : netfilter-test test.gilgil.net");
}


int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage();
        return -1;
    }
    HostAddr = argv[1];
    host_size = strlen(HostAddr);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { // packet copy code
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
