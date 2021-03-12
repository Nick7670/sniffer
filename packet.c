#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <mysql/mysql.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <signal.h>

#define MAXSIZE 8192
#define CMAX    256
#define OPTNUM  9
#define ON      1
#define OFF     0
#define DEF_IF  "en0"
#define FILTER_ARP(_p) (filter.flg[IP_ADDR] ?\
                       ((*(int *) (_p)->arp_spa == filter.ip.s_addr\
                         || *(int *) (_p)->arp_tpa == filter.ip.s_addr) ?\
                        1 : 0)\
                       : 1)
#define FILTER_IP(_p) (filter.flg[IP_ADDR] ?\
                       (((_p)->ip_src.s_addr == filter.ip.s_addr\
                         || (_p)->ip_dst.s_addr == filter.ip.s_addr) ?\
                        1 : 0)\
                       : 1)
#define FILTER_TCP(_p) (filter.flg[PORT] ?\
                        (((_p)->th_sport == filter.port\
                          || (_p)->th_dport == filter.port) ?\
                         1 : 0)\
                        : 1)
#define FILTER_UDP(_p) (filter.flg[PORT] ?\
                        (((_p)->uh_sport == filter.port\
                          || (_p)->uh_dport == filter.port) ?\
                         1 : 0)\
                        : 1)

struct total_ip
{
    int ip_broadcast;
    int ip_byte;
    int ip_packet;

};
struct total_udp
{
    int udp_packet;
};
struct total_tcp
{
    int tcp_packet;
};
struct total_icmp
{
    int icmp_packet;
    int icmp_redirect;
    int icmp_unreachable;
};
struct total_arp
{
    int arp_packet;
};

struct total_mac
{
    int mac_broad;
    int mac_short;
    int mac_long;
    int mac_byte;
    int mac_packet;
    int mac_byte_speed;//统计速度
    float mac_packet_speed;//统计速度

};
struct filter 
{
    struct in_addr ip;
    u_int16_t port;
    int flg[2];
};

enum {ETHER, ARP, IP, TCP, UDP, ICMP, DUMP, ALL, TIME};
enum {IP_ADDR, PORT};

void print_ethernet(struct ether_header* eth);
void print_arp(struct ether_arp* arp);
void print_ip(struct ip* ip);
void print_icmp(struct icmp* icmp);
void print_tcp(struct tcphdr* tcp);
void print_tcp_mini(struct tcphdr* tcp);
void print_udp(struct udphdr* udp);
char* mac_ntoa(u_char* d);
char* tcp_ftoa(int flag);
char* ip_ttoa(int flag);
char* ip_ftoa(int flag);
void help(char* cmd);
int t_mysql(u_char* mac_addr);
void statistic_eth(struct total_mac* t_mac,int len,time_t starttime,char* dhost);
void statistic_arp(struct total_arp* t_arp);
void statistic_ip(struct total_ip* t_ip,struct ip* p);
void statistic_udp(struct total_udp* t_udp);
void statisitc_icmp(struct total_icmp* t_icmp,struct icmp* p_icmp);
void statistic_tcp(struct total_tcp* t_tcp);
void handler();

int flag=0;

int main(int argc, char** argv)
{
    int s_fd;
    int c;  
    int opt[OPTNUM];       
    extern int optind;     
    time_t starttime=time(NULL)-1;
    time_t endtime;

    struct filter filter;
    struct total_mac* t_mac=(struct total_mac*)malloc(sizeof(struct total_mac));
    struct total_ip* t_ip=(struct total_ip*)malloc(sizeof(struct total_ip));
    struct total_udp* t_udp=(struct total_udp*)malloc(sizeof(struct total_udp));
    struct total_tcp* t_tcp=(struct total_tcp*)malloc(sizeof(struct total_tcp));
    struct total_icmp* t_icmp=(struct total_icmp*)malloc(sizeof(struct total_icmp));
    struct total_arp* t_arp=(struct total_arp*)malloc(sizeof(struct total_arp));

    opt[ETHER] = OFF;
    opt[ARP] = OFF;
    opt[IP] = OFF;
    opt[TCP] = OFF;
    opt[UDP] = OFF;
    opt[ICMP] = OFF;
    opt[DUMP] = OFF;
    opt[ALL] = OFF;
    opt[TIME] = OFF;

    filter.flg[IP_ADDR] = OFF;
    filter.flg[PORT] = OFF;

    while ((c = getopt(argc, argv, "aep:f:hft")) != EOF) {
        switch (c) {
        case 'a':  /* all */
            opt[ALL] = ON;
            break;
        case 'e':  /* ethernet */
            opt[ETHER] = ON;
            break;
        case 't':  /* time */
            opt[TIME] = ON;
            break;
        case 'p':  /* protocol */
            opt[ARP] = OFF;
            opt[IP] = OFF;
            opt[TCP] = OFF;
            opt[UDP] = OFF;
            opt[ICMP] = OFF;
            optind--;
            while (argv[optind] != NULL && argv[optind][0] != '-') 
            {
                if (strcmp(argv[optind], "arp") == 0)
                {
                    opt[ARP] = ON;
                }
                else if (strcmp(argv[optind], "ip") == 0)
                {
                    opt[IP] = ON;
                }
                else if (strcmp(argv[optind], "tcp") == 0)
                {    
                    opt[TCP] = ON;
                }
                
                else if (strcmp(argv[optind], "udp") == 0)
                {
                    opt[UDP] = ON;
                }
                else if (strcmp(argv[optind], "icmp") == 0)
                {
                    opt[ICMP] = ON;
                }
                else if (strcmp(argv[optind], "other") == 0)
                    ;
                else 
                {
                    help(argv[0]);
                    exit(EXIT_FAILURE);
                }
                optind++;
            }
            break;
        case 'f':  /* filter */
            optind--;
            while (argv[optind] != NULL && argv[optind][0] != '-')
            {
                if (strcmp(argv[optind], "ip") == 0 && argv[optind + 1] != NULL)
                {
                    filter.flg[IP_ADDR] = ON;                       
                    filter.ip.s_addr = inet_addr(argv[++optind]);   //将字符串形式的IP地址 -> 网络字节顺序 的整型值
                }
                else if (strcmp(argv[optind], "port") == 0 && argv[optind + 1] != NULL)
                {
                    filter.flg[PORT] = ON;                          
                    filter.port = htons(atoi(argv[++optind]));      //atoi将字符串转化为整数 htons将整型变量从主机字节顺序转变成网络字节顺序
                }
                else
                {
                    help(argv[0]);
                    exit(EXIT_FAILURE);
                }
                optind++;
            }
            break;
        case 'h':
        case '?':
        default:
            help(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }

    if (optind < argc) 
    {
        while (optind < argc)
        {
            printf("%s ", argv[optind++]);
        }
        printf("\n");
        help(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (filter.flg[IP_ADDR])
    {
        printf("filter ip   = %s\n", inet_ntoa(filter.ip));
    }
    if (filter.flg[PORT])
    {
        printf("filter port = %d\n", htons(filter.port));
    }
    if ((s_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) //使用sock_packet 抓取所有的包
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }


    struct sigaction siga;
    memset(&siga, 0, sizeof(siga));
    siga.sa_handler = handler;
    siga.sa_flags |= (SA_RESTART|SA_RESETHAND);//系统调用被信号打断时，重启系统调用（慢速系统调用）
    sigemptyset(&siga.sa_mask);
    sigaction(SIGINT, &siga, NULL);

    while (1) 
    {
        if(flag==1)
        {
            break;
        }
        struct ether_header* eth;
        struct ether_arp* arp; 
        struct ip* ip;      
        struct icmp* icmp;   
        struct tcphdr* tcp;        
        struct udphdr* udp;

        char buff[MAXSIZE];       
        void* p;                  
        void* p0;                
        int len;                   
        int disp;
        struct timeval tv;         
        struct tm tm; 

        if ((len = read(s_fd, buff, MAXSIZE)) < 0)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }
        gettimeofday(&tv, NULL);
        localtime_r((time_t*)&tv.tv_sec, &tm);
        p = p0 = buff;
        disp = OFF;

        eth = (struct ether_header*)p;
        p += sizeof(struct ether_header);
        statistic_eth(t_mac,len,starttime,eth->ether_dhost);   //统计模块 以太网
	if(opt[ETHER]==ON)
	{
	    disp=ON;
	}
        t_mysql(eth->ether_dhost);//对每一个包的mac地址在数据库中进行匹配
        t_mysql(eth->ether_shost);
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) //arp包
        {

            arp = (struct ether_arp*)p;
            statistic_arp(t_arp);                       //arp报文统计
            if (opt[ARP] == ON && FILTER_ARP(arp))
            {
                disp = ON;
            }
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP) //Ip包
        {
            ip = (struct ip*)p;
            p += ((int)(ip->ip_hl) << 2);
            statistic_ip(t_ip,ip);
            
            if (!FILTER_IP(ip))
            {
                continue;
            }
            if (opt[IP] == ON && opt[TCP] != ON && opt[UDP] != ON && opt[ICMP] != ON)
            {
                disp = ON;
            }
            switch (ip->ip_p) //判断应用层的协议是什么
            {
            case IPPROTO_TCP:
                tcp = (struct tcphdr*)p;
                p += ((int)(tcp->th_off) << 2);

                statistic_tcp(t_tcp);

                if (!FILTER_TCP(tcp))
                {
                    continue;
                }
                if (opt[TCP] == ON)
                {
                    disp = ON;
                }
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr*)p;
                p += sizeof(struct udphdr);
                statistic_udp(t_udp);

                if (!FILTER_UDP(udp))
                {
                    continue;
                }
                if (opt[UDP] == ON)
                {
                    disp = ON;
                }
                break;

            case IPPROTO_ICMP:
                icmp = (struct icmp*)p;
                p = icmp->icmp_data;
                statisitc_icmp(t_icmp,icmp);
                if (opt[ICMP] == ON)
                {
                    disp = ON;
                }
                break;
            default:
                if (opt[ALL] == ON)
                {
                    disp = ON;
                }
                break;
            }
        }
        else if (opt[ETHER] == ON && opt[ALL] == ON)//判断应用层的协议是什么
        {
            disp = ON;
        }

        if (disp == ON || opt[ALL] == ON) 
        {
            if (opt[TIME] == ON)
            {
                printf("Time: %02d:%02d:%02d.%06d\n", tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec);
            }
            if (opt[ETHER] == ON) 
            {
                print_ethernet(eth);
            }
            if (ntohs(eth->ether_type) == ETHERTYPE_ARP && opt[ARP] == ON) 
            {
                print_arp(arp);
            }
            else if (ntohs(eth->ether_type) == ETHERTYPE_IP) 
            {
                if (opt[IP] == ON)
                {
                    print_ip(ip);
                }
                if (ip->ip_p == IPPROTO_TCP && opt[TCP] == ON) 
                {
                    print_tcp(tcp);
                }
                else if (ip->ip_p == IPPROTO_UDP && opt[UDP] == ON) 
                {
                    print_udp(udp);
                }
                else if (ip->ip_p == IPPROTO_ICMP && opt[ICMP] == ON)
                {
                    print_icmp(icmp);
                }
                else if (opt[ALL] == ON) 
                {
                    printf("Protocol: unknown\n");
                }
            }
            else if (opt[ALL] == ON)
            {
                printf("Protocol: unknown\n");
            }
            printf("\n");
        }
        
    }

    time_t etime;
    time(&etime);
    printf("start time: %s\n",ctime(&starttime));
    printf("end time: %s\n",ctime(&etime));
    printf("mac packet: %d\n",t_mac->mac_packet);
    printf("mac short: %d\n",t_mac->mac_short);
    printf("mac long: %d\n",t_mac->mac_long);
    printf("mac broad: %d\n",t_mac->mac_broad);
    printf("mac byte: %d\n",t_mac->mac_byte);
    printf("mac bytespeed: %d\n",t_mac->mac_byte_speed);
    printf("mac packetspeed: %f\n",t_mac->mac_packet_speed);
    printf("ip packet: %d\n",t_ip->ip_packet);
    printf("ip broadcast: %d\n",t_ip->ip_broadcast);
    printf("ip byte: %d\n",t_ip->ip_byte);
    printf("icmp packet: %d\n",t_icmp->icmp_packet);
    printf("icmp unreachable: %d\n",t_icmp->icmp_unreachable);
    printf("icmp redirect: %d\n",t_icmp->icmp_redirect);
    printf("tcp packet: %d\n",t_tcp->tcp_packet);
    printf("udp packet: %d\n",t_udp->udp_packet);
    printf("arp packet: %d\n",t_arp->arp_packet);

    free(t_mac);
    free(t_ip);
    free(t_icmp);
    free(t_udp);
    free(t_tcp);
    free(t_arp);

    return 0;
}

char* mac_ntoa(u_char* d)
{
    #define MAX_MACSTR 50
    static char str[MAX_MACSTR]; 
    snprintf(str, MAX_MACSTR, "%02x:%02x:%02x:%02x:%02x:%02x",d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}

void print_ethernet(struct ether_header* eth)
{
    int type = ntohs(eth->ether_type);

    if (type <= 1500)
    {
        printf("IEEE 802.3 Ethernet Frame:\n");
    }
    else
    {
        printf("Ethernet Frame:\n");
    }
    printf("+-------------------------+-------------------------""+-------------------------+\n");
    printf("| Destination MAC Address:                          ""         %17s|\n", mac_ntoa(eth->ether_dhost));
    printf("+-------------------------+-------------------------""+-------------------------+\n");
    printf("| Source MAC Address:                               ""         %17s|\n", mac_ntoa(eth->ether_shost));
    printf("+-------------------------+-------------------------""+-------------------------+\n");
    if (type < 1500)
    {
        printf("| Length:            %5u|\n", type);
    }
    else
    {
        printf("| Ethernet Type:    0x%04x|\n", type);
    }
    printf("+-------------------------+\n");
}

void print_arp(struct ether_arp* arp)
{
    static char* arp_op_name[] =
    {
        "Undefine",
        "(ARP Request)",
        "(ARP Reply)",
        "(RARP Request)",
        "(RARP Reply)"
    };

#define ARP_OP_MAX (sizeof(arp_op_name) / sizeof(arp_op_name[0]))

    /* ARP protocol opcodes. */
//#define ARPOP_REQUEST 1  /* ARP request.  */
//#define ARPOP_REPLY 2  /* ARP reply.  */
//#define ARPOP_RREQUEST 3  /* RARP request.  */
//#define ARPOP_RREPLY 4  /* RARP reply.  */
//#define ARPOP_InREQUEST 8  /* InARP request.  */
//#define ARPOP_InREPLY 9  /* InARP reply.  */
//#define ARPOP_NAK 10  /* (ATM)ARP NAK.  */

    int op = ntohs(arp->ea_hdr.ar_op);
    if (op < 0 || ARP_OP_MAX < op)
    {
        op = 0;
    }
    printf("Protocol: ARP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Hard Type: %2u%-11s| Protocol:0x%04x%-9s|\n",
        ntohs(arp->ea_hdr.ar_hrd),
        (ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER) ? "(Ethernet)" : "(Not Ether)",
        ntohs(arp->ea_hdr.ar_pro),
        (ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP) ? "(IP)" : "(Not IP)");
    printf("+------------+------------+-------------------------+\n");
    printf("| HardLen:%3u| Addr Len:%2u| OP: %4d%16s|\n",
        arp->ea_hdr.ar_hln, 
        arp->ea_hdr.ar_pln, 
        ntohs(arp->ea_hdr.ar_op),
        arp_op_name[op]);
    printf("+------------+------------+-------------------------"
        "+-------------------------+\n");
    printf("| Source MAC Address:                               "
        "         %17s|\n", mac_ntoa(arp->arp_sha));
    printf("+---------------------------------------------------"
        "+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n",
        inet_ntoa(*(struct in_addr*)&arp->arp_spa));
    printf("+---------------------------------------------------"
        "+-------------------------+\n");
    printf("| Destination MAC Address:                          "
        "         %17s|\n", mac_ntoa(arp->arp_tha));
    printf("+---------------------------------------------------"
        "+-------------------------+\n");
    printf("| Destination IP Address:            %15s|\n",
        inet_ntoa(*(struct in_addr*)&arp->arp_tpa));
    printf("+---------------------------------------------------+\n");
}

void print_ip(struct ip *ip)
{
  printf("Protocol: IP\n");
  printf("+-----+------+------------+-------------------------+\n");
  printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",ip->ip_v, ip->ip_hl, ip_ttoa(ip->ip_tos), ntohs(ip->ip_len));
  printf("+-----+------+------------+-------+-----------------+\n");
  printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",ntohs(ip->ip_id), ip_ftoa(ntohs(ip->ip_off)),ntohs(ip->ip_off) &IP_OFFMASK);
  printf("+------------+------------+-------+-----------------+\n");
  printf("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum));
  printf("+------------+------------+-------------------------+\n");
  printf("| Source IP Address:                 %15s|\n",inet_ntoa(*(struct in_addr *) &(ip->ip_src)));
  printf("+---------------------------------------------------+\n");
  printf("| Destination IP Address:            %15s|\n",inet_ntoa(*(struct in_addr *) &(ip->ip_dst)));
  printf("+---------------------------------------------------+\n");
}

char* ip_ftoa(int flag)
{
    static int  f[] = {'R', 'D', 'M'};  /* 显示段标志的字符 */
    #define IP_FLG_MAX (sizeof(f) / sizeof(f[0]))
    static char str[IP_FLG_MAX + 1];     /* 存储返回值的缓冲区 */
    unsigned int mask = 0x8000;         /* 掩码 */
    int i;                              /* 循环变量 */

    for (i = 0; i < IP_FLG_MAX; i++) 
    {
        if (((flag << i) & mask) != 0)
        {
            str[i] = f[i];
        }
        else
        {
            str[i] = '0';
        }
    }
    str[i] = '\0';
    return str;
}


char *ip_ttoa(int flag)
{
    static int  f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};  /* TOS域的字符串 */
    #define TOS_MAX (sizeof(f) / sizeof(f[0]))
    static char str[TOS_MAX + 1]; 
    unsigned int mask = 0x80;      /* tos域的掩码 */
    int i;                       /* 循环参数 */

    for (i = 0; i < TOS_MAX; i++) 
    {
        if (((flag << i) & mask) != 0)
        {
            str[i] = f[i];
        }
        else
        {
            str[i] = '0';
        }
    }
    str[i] = '\0';
    return str;
}

char *tcp_ftoa(int flag)
{
    static int  f[] = {'U', 'A', 'P', 'R', 'S', 'F'}; 
    #define TCP_FLG_MAX (sizeof(f) / sizeof(f[0]))
    static char str[TCP_FLG_MAX + 1];           /* 返回值缓冲区 */
    unsigned int mask = 1 << (TCP_FLG_MAX - 1);   /* 取出tcp协议标志的掩码 */
    int i;                                       /* 循环变量 */

    for (i = 0; i < TCP_FLG_MAX; i++) 
    {
        if (((flag << i) & mask) != 0)
        {
            str[i] = f[i];
        }
        else
        {
            str[i] = '0';
        }
    }
    str[i] = '\0';
    return str;
}
void print_icmp(struct icmp *icmp)
{
    static char *type_name[] = {
    "Echo Reply",               /* Type  0 */
    "Undefine",                 /* Type  1 */
    "Undefine",                 /* Type  2 */
    "Destination Unreachable",  /* Type  3 */
    "Source Quench",            /* Type  4 */
    "Redirect (change route)",  /* Type  5 */
    "Undefine",                 /* Type  6 */
    "Undefine",                 /* Type  7 */
    "Echo Request",             /* Type  8 */
    "Undefine",                 /* Type  9 */
    "Undefine",                 /* Type 10 */
    "Time Exceeded",            /* Type 11 */
    "Parameter Problem",        /* Type 12 */
    "Timestamp Request",        /* Type 13 */
    "Timestamp Reply",          /* Type 14 */
    "Information Request",      /* Type 15 */
    "Information Reply",        /* Type 16 */
    "Address Mask Request",     /* Type 17 */
    "Address Mask Reply",       /* Type 18 */
    "Unknown"                   /* Type 19 */
    };                          
    #define ICMP_TYPE_MAX (sizeof(type_name) / sizeof(type_name[0]))
    int type = icmp->icmp_type;

    if (type < 0 || ICMP_TYPE_MAX <= type)
    {
        type = ICMP_TYPE_MAX - 1;
    }
    printf("Protocol: ICMP (%s)\n", type_name[type]);
    printf("+------------+------------+-------------------------+\n");
    printf("| Type:   %3u| Code:   %3u| Checksum:          %5u|\n",icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum));
    printf("+------------+------------+-------------------------+\n");

    if (icmp->icmp_type == 0 || icmp->icmp_type == 8) 
    {
        printf("| Identification:    %5u| Sequence Number:   %5u|\n",ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
        printf("+-------------------------+-------------------------+\n");
    } 
    else if (icmp->icmp_type == 3) 
    {
        if (icmp->icmp_code == 4) 
        {
            printf("| void:          %5u| Next MTU:          %5u|\n",ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
            printf("+-------------------------+-------------------------+\n");
        } 
        else 
        {
            printf("| Unused:                                 %10lu|\n",(unsigned long) ntohl(icmp->icmp_void));
            printf("+-------------------------+-------------------------+\n");
        }
    } 
    else if (icmp->icmp_type == 5) 
    {
        printf("| Router IP Address:                 %15s|\n",inet_ntoa(*(struct in_addr *) &(icmp->icmp_gwaddr)));
        printf("+---------------------------------------------------+\n");
    } 
    else if (icmp->icmp_type == 11) 
    {
        printf("| Unused:                                 %10lu|\n",(unsigned long) ntohl(icmp->icmp_void));
        printf("+---------------------------------------------------+\n");
    }


    if (icmp->icmp_type == 3 || icmp->icmp_type == 5 || icmp->icmp_type == 11) 
    {
        struct ip *ip = (struct ip *) icmp->icmp_data;
        char *p = (char *) ip + ((int) (ip->ip_hl) << 2);

        print_ip(ip);
        switch (ip->ip_p) 
        {
            case IPPROTO_TCP:
            print_tcp_mini((struct tcphdr *) p);
            break;
            case IPPROTO_UDP:
            print_udp((struct udphdr *) p);
            break;
        }
    }
}

void print_tcp_mini(struct tcphdr *tcp)
{
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n",
            ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10lu|\n",
            (unsigned long) ntohl(tcp->th_seq));
    printf("+---------------------------------------------------+\n");
}

void print_tcp(struct tcphdr *tcp)
{
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n",
            ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10lu|\n",
            (unsigned long) ntohl(tcp->th_seq));
    printf("+---------------------------------------------------+\n");
    printf("| Acknowledgement Number:                 %10lu|\n",
            (unsigned long) ntohl(tcp->th_ack));
    printf("+------+---------+--------+-------------------------+\n");
    printf("| DO:%2u| Reserved|F:%6s| Window Size:       %5u|\n",
            tcp->th_off, tcp_ftoa(tcp->th_flags), ntohs(tcp->th_win));
    printf("+------+---------+--------+-------------------------+\n");
    printf("| Checksum:          %5u| Urgent Pointer:    %5u|\n",
            ntohs(tcp->th_sum), ntohs(tcp->th_urp));
    printf("+-------------------------+-------------------------+\n");
}

void print_udp(struct udphdr *udp)
{
    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n",
            ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n",
            ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
    printf("+-------------------------+-------------------------+\n");
}


void help(char *cmd)
{
    fprintf(stderr, "usage: %s [-aeht] [-p protocols] [-f filters]\n", cmd);
    fprintf(stderr, "protocols: arp ip icmp tcp udp other\n");
    fprintf(stderr, "filters: ip <ip addr> port <port number>\n");
}


int t_mysql(u_char* mac_add)//传入一个mac地址
{
    static char mac_addr[50];  /* 保存变换为字符串的mac地址 */
    snprintf(mac_addr, 50, "%02x%02x%02x%02x%02x%02x",mac_add[0], mac_add[1], mac_add[2], mac_add[3], mac_add[4], mac_add[5]);
    MYSQL* con=NULL;
    con=mysql_init(con);

    if(con==NULL)
    {
        exit(1);
    }
    char* url="localhost";
    char* user="root";
    char* passwd="";
    char* dbname="";
    char query[100]="select * from find where mac_address = \"";
    char insert[100]="insert into find (mac_address) values (\"";
    char kuohao[5]="\")";
    char yinghao[5]="\"";
    con=mysql_real_connect(con,url,user,passwd,dbname,3306,NULL,0);
    if(con==NULL)
    {
        exit(1);
    }
   //使用mysql_find 在表中进行查找，如果没有找到，执行插入操作

    strcat(query,mac_addr);     //加入mac地址
    strcat(query,yinghao);

    mysql_query(con,query);
    MYSQL_RES* result=mysql_store_result(con);
    MYSQL_FIELD* field=mysql_fetch_fields(result);
    MYSQL_ROW row=mysql_fetch_row(result);

    if(row==NULL)//说明没有查询到
    {
        //需要进行插入操作
        strcat(insert,mac_addr);
        strcat(insert,kuohao);
        mysql_query(con,insert);   
    }
    mysql_close(con);
    return 0;
}
void statistic_eth(struct total_mac* mac,int len,time_t starttime,char* dhost)
{
    time_t endtime=time(NULL);
    mac->mac_packet++;
    mac->mac_byte+=len;
    if(mac->mac_packet!=0)
    {
        mac->mac_packet_speed=(float)((float)(mac->mac_packet)/(float)(endtime-starttime));
    }
    if(mac->mac_byte!=0)
    {
        mac->mac_byte_speed=(mac->mac_byte/(endtime-starttime));
    }
    if(len<64)
    {
        mac->mac_short++;
    }
    if(len>1518)
    {
        mac->mac_long++;
    }
    for(int i=0;i<6;i++)
    {
        if(dhost[i]!=0xff)
        {
            break;
        }
        if(i==5)
        {
            mac->mac_broad++;
        }
    }
}
void statistic_arp(struct total_arp* arp)
{
    arp->arp_packet++;
}

void statistic_ip(struct total_ip* t_ip,struct ip* p)
{
    t_ip->ip_packet++;
    t_ip->ip_byte+=p->ip_len;
    if(inet_ntoa(p->ip_dst)=="255.255.255.255")
    {
        t_ip->ip_broadcast++;
    }
}
void statistic_udp(struct total_udp* t_udp)
{
    t_udp->udp_packet++;
}

void statisitc_icmp(struct total_icmp* t_icmp,struct icmp* p_icmp)
{
    t_icmp->icmp_packet++;

    if(p_icmp->icmp_type==5)//类型为5说明发生了重定向
    {  
        t_icmp->icmp_redirect++;
    }
    else if(p_icmp->icmp_type==3)//类型为3说明主机不可达
    {
        t_icmp->icmp_unreachable++;
    }
}
void statistic_tcp(struct total_tcp* t_tcp)
{
    t_tcp->tcp_packet++;
}
void handler()
{
    flag=1;
}

 
