void packPacket(char * type, char * source, char * dest, char* ipsource, char* ipdest, int checksum, int payload);
u_int sum_bytes(int num_bytes, u_short * x);

#define ETHER_MAC 6
#define EHL 14
#define ETHER_IP 0x0800
#define IP_TCP 0x06
#define IP_UDP 0x11
#define UHL 8
#define OPT "-t"


 typedef struct ethhdr{
      u_char dst_mac[ETHER_MAC];//0
      u_char src_mac[ETHER_MAC];//6
      u_short ether_type;//
}ETHERNET;
    ETHERNET et;
 
  typedef struct iphdr{
     u_char ip_vhl;/* version << 4 | header length >> 2 */
     u_char ip_tos;/* type of service */
     u_short ip_len;/* total length */
     u_short ip_id;/* identification */
     u_short ip_off;/* fragment offset field */
 #define IP_RF 0x8000/* reserved fragment flag */
 #define IP_DF 0x4000/* dont fragment flag */
 #define IP_MF 0x2000/* more fragments flag */
 #define IP_OFFMASK 0x1fff/* mask for fragmenting bits */
    u_char ip_ttl;/* time to live */
    u_char ip_p;/* protocol */
    u_short ip_sum;/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
 }iphdr;

#define IP_HL(ip) (((ip) -> ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

    typedef struct tcphdr{
        u_short sport;
        u_short dport;
        u_int seq;
        u_int ack;
        u_char offset;
        #define TH_OFF(th) (((th) -> offset & 0xf0) >> 4)
        u_char flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short win;/* window */
        u_short sum;/* checksum */
        u_short urp;/* urgent pointer */
  }tcphdr;

typedef struct tcpchk{
    u_int src;
    u_int dest;
    u_char res;
    u_char proto;
    u_short len;
    tcphdr pay;
}tcpchk;

  typedef struct udphdr{
      unsigned short src;
      unsigned short dst;
  }udphdr;


u_short calculate_tcp_checksum(struct iphdr * iphdr, u_short tcp_len, tcphdr* tcp, u_short checksum);
