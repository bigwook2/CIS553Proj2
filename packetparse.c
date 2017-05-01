#include <stddef.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "packetparse.h" 
#include <assert.h>
#include <stdbool.h>

    u_short calculate_tcp_checksum(struct iphdr * iphdr,  u_short tcp_len, tcphdr *tcphdr , u_short checksum){
        u_int r = 0;
        u_int source = iphdr->ip_src.s_addr;
        u_int dest = iphdr->ip_dst.s_addr;
        r += sum_bytes(sizeof(int), &source); 
        r += sum_bytes(sizeof(int), &dest);
        
        r += htons(0x0006);

        r += htons(tcp_len); 
        
        u_int payload_sum = sum_bytes(tcp_len, tcphdr);
      //  printf("\npayload_sum: %x", payload_sum);
        r+= payload_sum;
       // printf("\nr before subtraction: %#x", r);
        r += ~checksum;
      //  printf("\n checksum = %#x\n r = %#x \n tcp_length = %#x",~checksum, r, htons(tcp_len));
       while(r >>16){

           r = (0xffff & r) +( r>>16);
        }
     // printf("\n returned value = %#x", r);
      assert((r & 0xffff0000) == 0x00000000);
       r = ~r;

        return (u_short) r;
    }        
    /*
     * @param num_bytes is the number of bytes that variable
     * x points to
     */
    u_int sum_bytes(int num_bytes,  u_short* x){
        int y = 0;
        char check_odd = num_bytes % 2;
        unsigned short z = 0;
        assert ((check_odd == 1) || (check_odd == 0));
        y  = check_odd ? (( num_bytes - 1)/2) : num_bytes/2;
        
        u_int r = 0;
        while(y != 0){
            y--;
            z = *(x);
           // z = ntohs(z);
      //     printf("\nAdd value: %#x", z);
            r += z;
            x++;
        }
        if(check_odd){
            z = *(x);
            
            z = z << 8;//shift left
            z = z & 0xff00;

       //     printf("\n check odd entered: %#x", z);
            r += z;

        }
        
       return r;
         
    }
int main(int argc, char *argv[] )
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pf;
  struct bpf_program fp;
  char select_mail[] = ""; 
  /*  char select_mail[] = "port 80";*/
  struct pcap_pkthdr h;
  const u_char *p;
  char buf[22];
  int num_packets = 0;
  int unknown_packets = 0;
  void exit();
  const char t_mode[2] = "-t";

  const char m_mode[2] = "-m";
  char t_flag = 0; 
  char m_flag = 0;
  char print_flag = 1;

  if(argc == 3) {
      if (strncmp(argv[2], t_mode, 2) == 0){
         strcpy(select_mail, "tcp"); 
         t_flag = 1;
         printf("\nTCP FLOW MODE");
      }
      else if (strncmp(argv[2],m_mode, 2) == 0){
         strcpy(select_mail, "tcp"); 
         m_flag = 1;
         printf("\nEMAIL TRAFFIC MODE");
      }

  }
  print_flag = !(m_flag || t_flag);
  //print_flag = 1;
   if( argc < 2  ){
    fprintf( stderr, "Usage: %s {pcap-file}\n", argv[0] );
    exit( 1 );
  }

  if( (pf = pcap_open_offline( argv[1], errbuf )) == NULL ){
    fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
    exit( 1 );
  }
  
  if( pcap_compile(pf, &fp, select_mail, 0, 0 ) == -1 ) {
    fprintf( stderr, "BPF compile errors on %s: %s\n",
	     select_mail, pcap_geterr(pf) );
    exit( 1 );
  }

  if( pcap_setfilter( pf, &fp ) == -1 ){
    fprintf( stderr, "Can't install filter '%s': %s\n", select_mail,
	     pcap_geterr(pf) );
    exit( 1 );
  }

 const ETHERNET *ether;
 const iphdr *ip;
 const tcphdr *tcp;
 const udphdr *udp;
 u_short checksum;
 u_short c_checksum;
 //struct ethhdr ether;
    int ihl;
    int thl;
    int uhl;
    int payload;
    u_short tcp_len;
  while( (p = pcap_next(pf, &h )) != NULL ){
      //printf("\n Cap Packet Length %d\nLen Packet Length %d",h.caplen, h.len); 
      num_packets++;
      printf("\n\n ******* Packet Number %d *******", num_packets);
      ether = (ETHERNET *)(p);//skipping preamble
      /**********Ethernet Header Handling ****************/
      
          u_short  etype = ntohs(ether->ether_type);
        if(print_flag){  
          printf("\nMac Destination: %02x : %02x : %02x: %02x: %02x: %02x", (ether->dst_mac[0]),( ether->dst_mac[1]),
            (ether->dst_mac[2]), (ether->dst_mac[3]), (ether->dst_mac[4]),( ether->dst_mac[5]));
          printf("\nMac Source:  %02x : %02x : %02x: %02x: %02x: %02x", (ether->src_mac[0]),( ether->src_mac[1]),
            (ether->src_mac[2]), (ether->src_mac[3]), (ether->src_mac[4]),( ether->src_mac[5]));
          //printf("\nChecking offset: %d", offsetof(ETHERNET, ether_type));
          printf("\nEthernet type: %04x",ntohs(ether->ether_type));
        }
      /*********IP Packet Handling ********************/
      if(etype != ETHER_IP){ 
         unknown_packets++; 
          continue;
      }
      
      ip = (iphdr*)(p+14);//ethernet is 14 bytes
      ihl = IP_HL(ip)*4;
      if(ihl < 20 ){
          printf("invalid ip header");
          return -1;
       }
        if(print_flag){  
          printf("\nIP Source: %s ", inet_ntoa(ip-> ip_src));
          
          printf("\nIP Destination: %s ", inet_ntoa(ip-> ip_dst));
        }
      
      /*********TCP Handler ***********************/
      if(ip ->ip_p== IP_TCP){
          tcp = (tcphdr*)(p+EHL+ihl);
          thl = TH_OFF(tcp)*4;
          if((thl< 20) || (thl > 60)){
              printf("invalid tcp header");
              return -1;
          }
          payload  = h.len-EHL-ihl-thl;
          tcp_len  = h.len - EHL-ihl;
          checksum = tcp-> sum;
          c_checksum = ntohs(calculate_tcp_checksum(ip, tcp_len, tcp, checksum))-0x0100;
          
        if(print_flag){  
              printf("\nTCP Source Port: %d \nTCP Destination Port:%d \nCalculated Checksum: %#x", ntohs(tcp->sport),ntohs(tcp->dport), c_checksum);
            if(checksum != htons(c_checksum)){
               printf("\nChecksum calculation was incorrect--information is not lossless");
               printf("\nExpected checksum: %#x", ntohs(checksum));
            }
            printf("\nPayload Size: %d", payload);
        }
      } 

      else if(ip -> ip_p == IP_UDP){
        udp  = (udphdr *) (p + EHL + ihl);
        
        if(print_flag){  
            printf("\nUDP Source Port: %d""\nUDP Destination Port: %d", ntohs(udp-> src), ntohs(udp -> dst)); 
            
            printf("\nPayload Size: %d", h.len-EHL-ihl-UHL);
        }
      }else{

        printf("\nPayload Size: %d", h.len-EHL-ihl);
        unknown_packets++;
      }

  }

    if(print_flag){  
      printf("\nNum of Unknown Packets: %d",unknown_packets);
      printf("\nNumber of packets parsed: %d\n",num_packets);
    }
    exit(0);
}

