/*
	master.c

	A master server for XreaL

	Copyright (C) 2002-2005  Mathieu Olivier

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include <stdarg.h>
#include <signal.h>
#include <ctype.h>

#ifndef WIN32
//#define _DEFAULT_SOURCE
#define _GNU_SOURCE
# include <pwd.h>
# include <unistd.h>
#endif

#include "common.h"
#include "messages.h"
#include "servers.h"


// ---------- Constants ---------- //

// Default master port
#define DEFAULT_MASTER_PORT_KP1     27900 //27900 hypo kingpin
#define DEFAULT_MASTER_PORT_KPQ3    27950 //kpq3 master port
#define DEFAULT_MASTER_PORT_GAMESPY 28900 //GameSpy master port


#ifndef WIN32
// Default path we use for chroot
# define DEFAULT_JAIL_PATH "/var/empty/"

// User we use by default for dropping super-user privileges
# define DEFAULT_LOW_PRIV_USER "nobody"
#endif



// ---------- Types ---------- //

#ifdef WIN32
//typedef int socklen_t;
#endif


// ---------- Private variables ---------- //

// The port we use
static unsigned short master_port_kp1 = DEFAULT_MASTER_PORT_KP1;
static unsigned short master_port_kpq3 = DEFAULT_MASTER_PORT_KPQ3;
static unsigned short master_port_gs = DEFAULT_MASTER_PORT_GAMESPY;

// Local address we listen on, if any
static const char *listen_name = NULL;
static struct in_addr listen_addr;

//static ip switch
static qboolean isStaticIPHost = qfalse;

//offline/web lists
static time_t   ping_dns_time = 0; //add hypo refresh dns
static time_t   ping_timoutSV_time = 0; //add hypo get server updates
static time_t   ping_list_time = 0; // ping offline/web list

//hypo console colors
#ifdef WIN32
static HANDLE hStdout;
#endif
// CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
//

#ifndef WIN32
// On UNIX systems, we can run as a daemon
static qboolean daemon_mode = qfalse;

// Path we use for chroot
static const char *jail_path = DEFAULT_JAIL_PATH;

// Low privileges user
static const char *low_priv_user = DEFAULT_LOW_PRIV_USER;
#endif

static qboolean exitNow = qfalse;

// ---------- Public variables ---------- //

// The master socket
SOCKET_NET		inSock_udp =   INVALID_SOCKET; // listen kp port
SOCKET_NET		inSock_kpq3 =  INVALID_SOCKET; // listen kpq3 port
SOCKET_NET		inSock_tcp =   INVALID_SOCKET; // in tcp
//USE_ALT_OUTPORT
SOCKET_NET		outSock_udp =  INVALID_SOCKET; // out kp
SOCKET_NET		outSock_kpq3 = INVALID_SOCKET; // out kpq3

clientTemp2_t clientinfo_tcp[MAX_CLIENTS];

// The current time (updated every time we receive a packet)
time_t          crt_time;


// Maximum level for a message to be printed
msg_level_t     max_msg_level = MSG_NORMAL;

// Peer address. We rebuild it every time we receive a new packet
char            peer_address[128];


// ---------- Private functions ---------- //

/*
====================
PrintPacket

Print the contents of a packet on stdout
====================
*/
void PrintPacket(const char *packet, int length)
{
	char pket[MAX_PACKET_SIZE_RECV * 4 + 32];
	int  pos = 0;
	qbyte c;
	int  i;

	pket[pos++] = '\"';

	for (i = 0; i < length; i++)
	{
		c = packet[i];
		if (c < 32 || c > 127)
			pos += snprintf(pket + pos, sizeof(pket) - pos, "\\x%02X", c);
		else
			pket[pos++] = c;
	}

	pos += snprintf(pket + pos, sizeof(pket) - pos, "\" (%04d bytes)\n", length);
	MsgPrint(MSG_NOPRINT | MSG_COL_3_BROWN, "%s", pket);
}


/*
====================
SocketError_close

close socket, depending on compiler

type =
0 perminate sockets
1 temp client socket
2 temp web socket
====================
*/
 void SocketError_close(SOCKET_NET socket, int type, int index)
{
	int ret;

#ifdef WIN32
	ret = closesocket(socket);
#else
	ret = close(socket);
#endif

	if (ret)
		MsgPrint(MSG_WARNING, "WARNING. Cant close socket %i \n", socket);

	switch (type)
	{
		case SOCKET_CLIENT:
			clientinfo_tcp[index].socknum = INVALID_SOCKET;
			clientinfo_tcp[index].timeout = 0;
			break;

		default:
			break;
	}

}

/*
====================
FloodIpStoreReject

Close TCP Socket with client flood
====================
*/
static qboolean FloodIpStoreReject( struct sockaddr_in *address )
{
	static int i, j;
	static clientTemp_t client;
	static clientIpCheck_t cli_info[IP_CYCLE_LIST_COUNT];

#if 1
	i = client.currentNum;
	j = 0;
	do 
	{
		/*check if client exists*/
		if ( !(cli_info[i].from == NULL) && 
			cli_info[i].from->sin_addr.s_addr == address->sin_addr.s_addr)
		{
			if (cli_info[i].lastPingTime < crt_time)	{
				cli_info[i].lastPingTime = crt_time;
				cli_info[i].count = 0;
			}

			if (cli_info[i].count > 6)	{
				cli_info[i].lastPingTime = crt_time + 3;

				return qtrue; //flood. ignore
			}

			cli_info[i].lastPingTime += 1;
			cli_info[i].count++;
			return qfalse; //return servers
		}

		i++;
		if (i >= IP_CYCLE_LIST_COUNT)
			i = 0;
		j++;

	} while (j < IP_CYCLE_LIST_COUNT);

	//cycle through list
	client.currentNum++;
	if (client.currentNum >= IP_CYCLE_LIST_COUNT)
		client.currentNum = 0;

	//client not in list
	cli_info[client.currentNum].from = address;
	cli_info[client.currentNum].lastPingTime = crt_time;

	return qfalse;
#endif
}

/*
====================
SysInit

System dependent initializations
====================
*/
static qboolean SysInit(void)
{
#ifdef WIN32
	WSADATA         winsockdata;

	if(WSAStartup(MAKEWORD(1, 1), &winsockdata))
	{
		MsgPrint(MSG_ERROR, "ERROR: can\'t initialize winsocks\n");
		return qfalse;
	}
#endif

	return qtrue;
}


/*
====================
UnsecureInit

System independent initializations, called BEFORE the security initializations.
We need this intermediate step because DNS requests may not be able to resolve
after the security initializations, due to chroot.
====================
*/
static qboolean UnsecureInit(void)
{
	// Resolve the address mapping list
	if(!Sv_ResolveAddressMappings())
		return qfalse;

	// Resolve the listen address if one was specified
	if(listen_name != NULL)
	{
		struct hostent *itf;

		itf = gethostbyname(listen_name);
		if(itf == NULL)
		{
			MsgPrint(MSG_ERROR, "ERROR: can\'t resolve %s \n", listen_name);
			return qfalse;
		}
		if(itf->h_addrtype != AF_INET)
		{
			MsgPrint(MSG_ERROR, "ERROR: %s is not an IPv4 address \n", listen_name);
			return qfalse;
		}

		memcpy(&listen_addr.s_addr, itf->h_addr_list[0], sizeof(listen_addr.s_addr));
	}

	return qtrue;
}


/*
====================
SecInit

Security initializations (system dependent)
====================
*/
static qboolean SecInit(void)
{
#ifndef WIN32
	// Should we run as a daemon?
	if(daemon_mode && daemon(0, 0))
	{
		MsgPrint(MSG_NOPRINT, "ERROR: daemonization failed (%s)\n", strerror(errno));
		return qfalse;
	}

	// UNIX allows us to be completely paranoid, so let's go for it
	if(geteuid() == 0)
	{
		struct passwd  *pw;

		MsgPrint(MSG_WARNING, "WARNING: running with super-user privileges\n");

		// We must get the account infos before the calls to chroot and chdir
		pw = getpwnam(low_priv_user);
		if(pw == NULL)
		{
			MsgPrint(MSG_ERROR, "ERROR: can\'t get user \"%s\" properties\n", low_priv_user);
			return qfalse;
		}

		// Chroot ourself
		MsgPrint(MSG_NORMAL, "  - chrooting myself to %s... ", jail_path);
		if(chroot(jail_path) || chdir("/"))
		{
			MsgPrint(MSG_ERROR, "FAILED (%s)\n", strerror(errno));
			return qfalse;
		}
		MsgPrint(MSG_NORMAL, "succeeded\n");

		// Switch to lower privileges
		MsgPrint(MSG_NORMAL, "  - switching to user \"%s\" privileges... ", low_priv_user);
		if(setgid(pw->pw_gid) || setuid(pw->pw_uid))
		{
			MsgPrint(MSG_ERROR, "FAILED (%s)\n", strerror(errno));
			return qfalse;
		}
		MsgPrint(MSG_NORMAL, "succeeded (UID: %u, GID: %u)\n", pw->pw_uid, pw->pw_gid);

		MsgPrint(MSG_NORMAL, "\n");
	}
#endif

	return qtrue;
}


/*
====================
ParseCommandLine

Parse the options passed by the command line
====================
*/
static qboolean ParseCommandLine(int argc, const char *argv[])
{
	int             ind = 1;
	unsigned int    vlevel = max_msg_level;
	qboolean        valid_options = qtrue;

	while(ind < argc && valid_options)
	{
		// If it doesn't even look like an option, why bother?
		if(argv[ind][0] != '-')
			valid_options = qfalse;

		else
			switch (argv[ind][1])
			{
#ifndef WIN32
					// Daemon mode
				case 'D':
					daemon_mode = qtrue;
					break;
#endif

					// Help
				case 'h':
					valid_options = qfalse;
					break;

					// Hash size
				case 'H':
					ind++;
					if(ind < argc)
						valid_options = Sv_SetHashSize(atoi(argv[ind]));
					else
						valid_options = qfalse;
					break;

#ifndef WIN32
					// Jail path
				case 'j':
					ind++;
					if(ind < argc)
						jail_path = argv[ind];
					else
						valid_options = qfalse;
					break;
#endif

					// Listen address
				case 'l':
					ind++;
					if(ind >= argc || argv[ind][0] == '\0')
						valid_options = qfalse;
					else
						listen_name = argv[ind];
					break;

					// Address mapping
				case 'm':
					ind++;
					if(ind < argc)
						valid_options = Sv_Add_unResolvedAddressMapping(argv[ind]);
					else
						valid_options = qfalse;
					break;

					// Maximum number of servers
				case 'n':
					ind++;
					if(ind < argc)
						valid_options = Sv_SetMaxNbServers(atoi(argv[ind]));
					else
						valid_options = qfalse;
					break;

					// Port number
				case 'p':
				{
					unsigned short  port_num = 0;

					ind++;
					if(ind < argc)
						port_num = (unsigned short)atoi(argv[ind]);
					if(!port_num)
						valid_options = qfalse;
					else
						master_port_kp1 = port_num;
					break;
				}
				case 'q':
				{
					unsigned short  port_num_kpq3 = 0;

					ind++;
					if(ind < argc)
						port_num_kpq3 = (unsigned short)atoi(argv[ind]);
					if (!port_num_kpq3)
						valid_options = qfalse;
					else
						master_port_kpq3 = port_num_kpq3;
					break;
				}
#ifndef WIN32
					// Low privileges user
				case 'u':
					ind++;
					if(ind < argc)
						low_priv_user = argv[ind];
					else
						valid_options = qfalse;
					break;
#endif

					// Verbose level
				case 'v':
					// If a verbose level has been specified
					if(ind + 1 < argc && argv[ind + 1][0] != '-')
					{
						ind++;
						vlevel = atoi(argv[ind]);
						if(vlevel > MSG_DEBUG)
							valid_options = qfalse;
					}
					else
						vlevel = MSG_DEBUG;
					break;

					//static ip
				case 's':
					isStaticIPHost = qtrue;
					break;

				default:
					valid_options = qfalse;
			}

		ind++;
	}

	// If the command line is OK, we can set the verbose level now
	if(valid_options)
	{
#ifndef WIN32
		// If we run as a daemon, don't bother printing anything
		if(daemon_mode)
			max_msg_level = MSG_NOPRINT;
		else
#endif
			max_msg_level = vlevel;
	}

	return valid_options;
}


/*
====================
PrintHelp

Print the command line syntax and the available options
====================
*/
static void PrintHelp(void)
{
	MsgPrint(MSG_ERROR, "Syntax: Kingpinmaster [options]\n" "Available options are:\n"
#ifndef WIN32
			 "  -D               : run as a daemon\n"
#endif
			 "  -h               : this help\n" "  -H <hash_size>   : hash size in bits, up to %u (default: %u)\n"
#ifndef WIN32
			 "  -j <jail_path>   : use <jail_path> as chroot path (default: %s)\n"
			 "                     only available when running with super-user privileges\n"
#endif
			 "  -l <address>     : listen on local address <address>\n"
			 "  -m <a1>=<a2>     : map address <a1> to <a2> when sending it to clients\n"
			 "                     addresses can contain a port number (ex: myaddr.net:1234)\n"
			 "  -n <max_servers> : maximum number of servers recorded (default: %u)\n"
			 "  -p <port_num>    : Kingpin:   use port <port_num> (default: %u)\n"
			 "  -q <port_num>    : KingpinQ3: use port <port_num> (default: %u)\n"
#ifndef WIN32
			 "  -u <user>        : use <user> privileges (default: %s)\n"
			 "                     only available when running with super-user privileges\n"
#endif
		"  -v [verbose_lvl] : verbose level, up to %u (default: %u) (no value = %u)\n"
			 "\n", MAX_HASH_SIZE, DEFAULT_HASH_SIZE,
#ifndef WIN32
			 DEFAULT_JAIL_PATH,
#endif
			 DEFAULT_MAX_NB_SERVERS, DEFAULT_MASTER_PORT_KP1, DEFAULT_MASTER_PORT_KPQ3,
#ifndef WIN32
			 DEFAULT_LOW_PRIV_USER,
#endif
			 MSG_DEBUG, MSG_NORMAL, MSG_DEBUG);
}


void InitSockets(SOCKET *sock, int dGram, int ipProto, char* socName)
{
	*sock = socket(PF_INET, dGram, ipProto);
	if (*sock == INVALID_SOCKET)	{
		MsgPrint(MSG_ERROR, "ERROR: %s creation failed (%s)\n", socName, strerror(errno));
	}
}

void InitBindSockets(struct sockaddr_in address, SOCKET *sock, unsigned short master_port, char * portMsg, char * gameMsg)
{
	address.sin_port = htons(master_port);
	if (bind((*sock), (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s) \n", strerror(errno));
		SocketError_close(*sock, 0, 0);
		*sock = INVALID_SOCKET;
	}
	MsgPrint(MSG_NORMAL|MSG_COL_3_BROWN, "%s port %hu -=(  %s  )=- \n", portMsg, ntohs(address.sin_port), gameMsg);
}

/*
====================
SecureInit

System independent initializations, called AFTER the security initializations
====================
*/
static qboolean SecureInit(void)
{
	struct sockaddr_in address;

	// Init the time and the random seed
	crt_time = time(NULL);
	srand( (unsigned)crt_time );

	// Initialize the server list and hash table
	if(!Sv_Init())
		return qfalse;

#ifdef WIN32
	//console colors
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
	MsgPrint(MSG_NORMAL, "-==========================================-\n");

	////////////////////////////////////////////////////////
	//  set IP address
	////////////////////////////////////////////////////////
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	if(listen_name != NULL)
	{
		MsgPrint(MSG_NORMAL|MSG_COL_3_BROWN, "Listening on address %s (%s) \n", listen_name, inet_ntoa(listen_addr));
		address.sin_addr.s_addr = listen_addr.s_addr;
	}
	else
		address.sin_addr.s_addr = htonl(INADDR_ANY);  //tcp only use any ip?


	////////////////////////////////////////////////////////
	// create sockets.
	////////////////////////////////////////////////////////
	InitSockets(&inSock_udp, SOCK_DGRAM, IPPROTO_UDP, "inSock_udp");
	InitSockets(&inSock_kpq3, SOCK_DGRAM, IPPROTO_UDP, "inSock_kpq3");
	InitSockets(&inSock_tcp, SOCK_STREAM, IPPROTO_TCP, "inSock_tcp"); //gamespy TCP
	if (!inSock_udp || !inSock_kpq3 || !inSock_tcp)
		return qfalse;

#ifdef USE_ALT_OUTPORT
	InitSockets(&outSock_udp, SOCK_DGRAM, IPPROTO_UDP, "outSock_udp");
	InitSockets(&outSock_kpq3, SOCK_DGRAM, IPPROTO_UDP, "outSock_kpq3");
	if (!outSock_udp || !outSock_kpq3)
		return qfalse;
#endif


	////////////////////////////////////////////////////////
	//  Bind sockets
	////////////////////////////////////////////////////////
	InitBindSockets(address, &inSock_udp, master_port_kp1, "Listening   UDP", "Kingpin");
	InitBindSockets(address, &inSock_kpq3, master_port_kpq3, "Listening   UDP", "KingpinQ3");
	InitBindSockets(address, &inSock_tcp, master_port_gs, "Listening   TCP", "Gamespy");
	if (!inSock_udp || !inSock_kpq3 || !inSock_tcp)
		return qfalse;
#ifdef USE_ALT_OUTPORT
	// Deliberately use a different port for outgoing traffic in order
	// to confuse NAT UDP "connection" tracking and thus delist servers
	// hidden by NAT
	InitBindSockets(address, &outSock_udp, master_port_kp1+1, "Server out  UDP", "Kingpin");
	InitBindSockets(address, &outSock_kpq3, master_port_kpq3+1, "Server out  UDP", "KingpinQ3");
	if (!outSock_udp || !outSock_kpq3)
		return qfalse;
#endif


	////////////////////////////////////////////////////////
	// listen on TCP for gamespy
	////////////////////////////////////////////////////////
	//open listen port
	if (listen(inSock_tcp, MAX_CLIENTS*2) == SOCKET_ERROR) {//hypo todo: test. is 16 enough?
		MsgPrint(MSG_ERROR, "listen(): Error listening on socket (%s). \n", strerror(errno));
		SocketError_close(inSock_tcp, 0, 0);
		return qfalse;
	}
	// end tcp Gamespy
	////////////////////////////////////////////////////////

	// increase socket buffer for big web lists
	{
		//getsockopt(inSock_udp, )
		int iResult = 0;

		int bOptVal = 2048*256;
		int bOptLen = sizeof(int);

		int iOptVal = 0;
		socklen_t iOptLen = sizeof(int);
		//bOptVal = TRUE;

		//						sock		int			int				char		int
		iResult = setsockopt(inSock_udp, SOL_SOCKET, SO_RCVBUF, (char *)&bOptVal, bOptLen);
		if (iResult !=SOCKET_ERROR)
		{
			iResult = getsockopt(inSock_udp, SOL_SOCKET, SO_RCVBUF, (void *)&iOptVal, &iOptLen);
			if (iResult !=SOCKET_ERROR)
				MsgPrint(MSG_NORMAL|MSG_COL_3_BROWN, "recv Buf:   %ld \n", iOptVal);
		}

		iResult = setsockopt(inSock_udp, SOL_SOCKET, SO_SNDBUF, (char *)&bOptVal, bOptLen);
		if (iResult != SOCKET_ERROR)
		{
			iResult = getsockopt(inSock_udp, SOL_SOCKET, SO_SNDBUF, (char *)&iOptVal, &iOptLen);
			if (iResult !=SOCKET_ERROR)		
			MsgPrint(MSG_NORMAL|MSG_COL_3_BROWN, "send Buf:   %ld \n", iOptVal);
		}

		//iResult = getsockopt(inSock_udp, SOL_SOCKET, SO_RCVBUF, (char *)&iOptVal, &iOptLen);
		//wprintf(L"SO_KEEPALIVE Value: %ld\n", iOptVal);
	}

	MsgPrint(MSG_NORMAL, "-==========================================-\n");
	MsgPrint(MSG_NORMAL, "listen() is OK, I\'m waiting for connections...\n");

	return qtrue;
} 



/*
===============
cleanUp

Clean up
===============
*/
static void cleanUp(int signal)
{
	MsgPrint(MSG_NORMAL, "Caught signal %d, exiting...\n", signal);

	exitNow = qtrue;
}


/*
====================
replaceNullChar

replace null with \
====================
*/
void replaceNullChar(char *packet, int packet_len)
{
	int i;

	for (i = 0; i < packet_len; i++)
	{
		if (packet[i] == '\0')
			packet[i] = '\\';
	}
}



/*
====================
MAST_GlobalTimedEvent

Things to do while nothing is going on
====================
*/
static void MAST_GlobalTimedEvent(void)
{
	static short listIdx = 1; //get gameport(web) 1st
	int i;

	Sv_MemCheck("timed event start");

	//timeout clients
	for (i = 0; i < MAX_CLIENTS; i++)	
	{
		if (clientinfo_tcp[i].socknum != INVALID_SOCKET &&
			clientinfo_tcp[i].timeout > 0 && 
			clientinfo_tcp[i].timeout < crt_time) //add extra time?
		{
			char tmpIP[128];
			snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", 
				inet_ntoa(clientinfo_tcp[i].tmpClientAddress.sin_addr), 
				ntohs(clientinfo_tcp[i].tmpClientAddress.sin_port));
			MsgPrint(MSG_WARNING, "%-21s ---- %-22s Removed \n", tmpIP, "Client timed out.");
			SocketError_close(clientinfo_tcp[i].socknum, SOCKET_CLIENT, i);
		}
	}


	Sv_MemCheck("timed1");

	// hypo update servers about to time out. when no activity
	if (ping_timoutSV_time < crt_time)	
	{
		Sv_PingTimeOut_GamePort();
		ping_timoutSV_time = crt_time + 20; //check every 20 secs
	}


	//get servers from txt files
	if (ping_list_time < crt_time)
	{
		switch (listIdx)
		{
		case 0:
				CFG_Offline_Begin();
			break;
		case 1:
		case 2:
		default:
				WEB_Begin_Send();//game port
			break;
		}

		listIdx += 1;
		if (listIdx > 1)
			listIdx = 0;

		//update next refresh time
		ping_list_time = crt_time + REFRESH_TIME_WEBLIST;
	}


	Sv_MemCheck("timed4");

	// hypov8 try resolve dns names every 5 min(dynamic ip's)
	if (!isStaticIPHost)	
	{	
		if (ping_dns_time < crt_time) {
			Sv_ResolveAddressMappings();
			ping_dns_time = crt_time + REFRESH_TIME_DNS; //5 min
		}
	}

	Sv_MemCheck("timed5");

}

//compatability??
void Sys_Sleep(int ms)
{
#ifdef _WIN32
	Sleep((DWORD)ms);
#else
	usleep(1000*ms);
#endif

}

#ifdef _DEBUG
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		//exit.
		case CTRL_CLOSE_EVENT:
		case CTRL_BREAK_EVENT:
			printf("Ctrl-Close event\n\n");
			SV_ClearMem();
			CFG_ClearMem();
			return FALSE;

		default:
			return FALSE;
	}
}
#endif

/*
====================
main

Main function
====================
*/
int main(int argc, const char *argv[])
{
	struct sockaddr_in address;
	socklen_t       addrlen = sizeof(address);
	int             nb_bytes;
	SOCKET_NET      recv_sock, fd_sok;
	char            packet[MAX_PACKET_SIZE_RECV + 1];	// "+ 1" because we append a '\0'
	qboolean        valid_options;
	fd_set          rfds;
	struct timeval  tv;
	qboolean        isTCP, isKPQ3, isTCPClient, isWebList;
	int             iSendResult;
	int             i;
	int             sockCliNum, sockWebNum;

	//hypov8 initialize address
	address.sin_family = AF_INET;
	address.sin_port = 0;
	address.sin_addr.s_addr = htonl(INADDR_ANY);

	signal(SIGINT, cleanUp);
	signal(SIGTERM, cleanUp);

	// Get the options from the command line
	valid_options = ParseCommandLine(argc, argv);

	MsgPrint(MSG_NORMAL, "Kingpin master (version " KP_MASTER_VERSION " " __DATE__ " " __TIME__ ")\n");

	// If there was a mistake in the command line, print the help and exit
	if(!valid_options)
	{
		PrintHelp();
		MsgPrint(MSG_ERROR, "\n  --==  SHUTTING DOWN  ==--\n");
		Sys_Sleep(5000); //5 seconds
		return EXIT_FAILURE;
	}

	// Initializations
	if (!SysInit() || !UnsecureInit() || !SecInit() || !SecureInit())
	{
#ifdef _DEBUG
		SV_ClearMem();
		CFG_ClearMem();
#endif
		MsgPrint(MSG_ERROR, "\n  --==  SHUTTING DOWN  ==--\n");
		Sys_Sleep(5000); //5 seconds
		return EXIT_FAILURE;
	}
#ifdef _DEBUG
	if ( !( SetConsoleCtrlHandler(CtrlHandler, TRUE) ) )	
	{
		MsgPrint(MSG_ERROR, "\n  --==  SHUTTING DOWN  ==--\n");
		Sys_Sleep(5000); //5 seconds
		return EXIT_FAILURE;
	}
#endif

	MsgPrint(MSG_NORMAL, "\n");

	//initialise all client_socket[] to 0 so not checked
	for (i = 0; i < MAX_CLIENTS; i++){
		clientinfo_tcp[i].socknum = INVALID_SOCKET;
	}

	//inital startup. process offline/web_lists
	CFG_Init(); //allocate offline/ignore lists
	WEB_Init(); //startup curl/winhttp

	CFG_Offline_Begin(); //read ip_offline_gs.txt
	WEB_Begin_Send();    //read ip_weblist_gs.txt

	ping_list_time = crt_time + 20; //check next list sooner
	ping_dns_time = crt_time + REFRESH_TIME_DNS; //5 min

	// Until the end of times...
	while (!exitNow)
	{
		FD_ZERO(&rfds);
		FD_SET(inSock_udp, &rfds);
		FD_SET(inSock_kpq3, &rfds);
		FD_SET(inSock_tcp, &rfds);
#ifdef USE_ALT_OUTPORT
		FD_SET(outSock_udp, &rfds);
		FD_SET(outSock_kpq3, &rfds);
#endif

		//pick highest socket. linux. hypo note: dont know why it works, but it does :)
		fd_sok = inSock_udp;
		if (inSock_kpq3 > fd_sok)
			fd_sok = inSock_kpq3;
		if (inSock_tcp > fd_sok)
			fd_sok = inSock_tcp;
#ifdef USE_ALT_OUTPORT
		if (outSock_udp > fd_sok)
			fd_sok = outSock_udp;
		if (outSock_kpq3 > fd_sok)
			fd_sok = outSock_kpq3;
#endif
		//add child client sockets to set 
		for (i = 0; i < MAX_CLIENTS; i++)
		{
			if (clientinfo_tcp[i].socknum != INVALID_SOCKET) {
				FD_SET(clientinfo_tcp[i].socknum, &rfds);
				if (clientinfo_tcp[i].socknum > fd_sok)
					fd_sok = clientinfo_tcp[i].socknum;
			}
		}


		//hypov8 moved up. allow update pings to servers
		crt_time = time(NULL);
		tv.tv_sec = tv.tv_usec = 0;

		// Check for new data every 100ms
		iSendResult = select(fd_sok + 1, &rfds, NULL, NULL, &tv);
		if (iSendResult <= 0)
		{
			if (iSendResult < 0)
				MsgPrint(MSG_WARNING, "WARNING: TCP \'select\' socket Failed. (Error: %d) \n", ERRORNUM);

			//check weblists responce
			WEB_PollWebList();
			//run event's when there is nothing else to do
			MAST_GlobalTimedEvent();

			Sys_Sleep(100); //100 milliseconds
			continue;
		}


		isTCP = 0;
		isTCPClient = 0;
		isKPQ3 = 0;
		isWebList = 0;
		memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues
		recv_sock = INVALID_SOCKET;
		sockWebNum = 0;
		sockCliNum = 0;

		if (FD_ISSET(inSock_udp, &rfds))	{
			recv_sock = inSock_udp;
		}
		else if (FD_ISSET(inSock_kpq3, &rfds))	{
			isKPQ3 = 1;
			recv_sock = inSock_kpq3;
		}
		else if (FD_ISSET(inSock_tcp, &rfds))	{
			isTCP = 1;
			recv_sock = inSock_tcp;
		}
#ifdef USE_ALT_OUTPORT
		else if (FD_ISSET(outSock_udp, &rfds))	{
			 recv_sock = outSock_udp;
		}
		else if (FD_ISSET(outSock_kpq3, &rfds))	{
			isKPQ3 = 1;
			recv_sock = outSock_kpq3;
		}
#endif
		else
		{
			for (i = 0; i < MAX_CLIENTS; i++)
			{
				if (clientinfo_tcp[i].socknum != INVALID_SOCKET &&
					FD_ISSET(clientinfo_tcp[i].socknum, &rfds))
				{
					isTCPClient = 1;
					sockCliNum = i;
					break;
				}
			}
			if (i >= MAX_CLIENTS)
				continue; //no data??
		}


		// Get the next valid message
		if (isTCP)
		{
			time_t last = 0;
			int cliID = 0;

			//find free client. if full, clear oldest
			for (i = 0; i < MAX_CLIENTS; i++)
			{
				//free socket?
				if ( clientinfo_tcp[ i ].socknum == INVALID_SOCKET ) {
					cliID = i;
					break;
				}
				if ( last == 0 || clientinfo_tcp[ i ].timeout < last ) {
					last = clientinfo_tcp[ i ].timeout;
					cliID = i;
				}
			}

			if ( i >= MAX_CLIENTS )	{
				MsgPrint(MSG_WARNING, "WARNING. Client ports full. clearnig...\n");
				if (shutdown(clientinfo_tcp[cliID].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP \'shutdown\' Failed. (Error: %i)", ERRORNUM);
				SocketError_close(clientinfo_tcp[cliID].socknum, SOCKET_CLIENT, cliID);
			}

			//accept  new connection
			clientinfo_tcp[cliID].socknum = accept(recv_sock, (struct sockaddr *)&address, &addrlen);

			if (clientinfo_tcp[cliID].socknum == INVALID_SOCKET)	{
				MsgPrint(MSG_WARNING, "WARNING: TCP Acept Failed. (Error: %i)\n", ERRORNUM);
				SocketError_close(clientinfo_tcp[cliID].socknum, SOCKET_CLIENT, cliID);
				continue;
			}
			// Ignore abusers
			if (CFG_Ignore_Check(inet_ntoa(address.sin_addr)))	{
				char tmpIP[128];
				snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
				MsgPrint(MSG_WARNING, "%-21s ---> CLIENT: in ignore list \n", tmpIP);
				if (shutdown(clientinfo_tcp[cliID].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP \'shutdown\' Failed. (Error: %i)", ERRORNUM);
				SocketError_close(clientinfo_tcp[cliID].socknum, SOCKET_CLIENT, cliID);
				continue;
			}
			// prevent flooding
			if (FloodIpStoreReject(&address))	{
				char tmpIP[128];
				snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
				MsgPrint(MSG_WARNING, "%-21s ---> FLOOD: Client Rejected\n", tmpIP);
				if (shutdown(clientinfo_tcp[cliID].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP \'shutdown\' Failed. (Error: %i)", ERRORNUM);
				SocketError_close(clientinfo_tcp[cliID].socknum, SOCKET_CLIENT, cliID);
				continue;
			}

			//send empty packet then echo
			iSendResult = send(clientinfo_tcp[cliID].socknum, 0, 0, 0);
			iSendResult = send(clientinfo_tcp[cliID].socknum, M2B_ECHOREPLY, strlen(M2B_ECHOREPLY), 0);
			if (iSendResult == SOCKET_ERROR) 	{
				MsgPrint(MSG_WARNING, "WARNING: TCP Send echo Failed. (Error: %i) \n", ERRORNUM);
				SocketError_close(clientinfo_tcp[cliID].socknum, SOCKET_CLIENT, cliID);
				continue;
			}

			//set some defaults
			clientinfo_tcp[cliID].timeout = crt_time + TIMEOUT_PING;
			clientinfo_tcp[cliID].decrypt_str[0] = '\0';
			clientinfo_tcp[cliID].browser_type[0] = '\0';
			clientinfo_tcp[cliID].valid = qfalse;
			clientinfo_tcp[cliID].gsEncType = -1;
			memcpy(&clientinfo_tcp[cliID].tmpClientAddress, &address, addrlen);


			if (i > 0 && max_msg_level >= MSG_DEBUG)
				MsgPrint(MSG_WARNING, "*** NOTE ***: Multiple TCP ports used (count: %i) \n", i + 1);

			// inital packet, wait for next packet
			continue;
		}
		else if (isTCPClient) //existing conection, get packet
		{
			nb_bytes = recv(clientinfo_tcp[sockCliNum].socknum, packet, MAX_PACKET_SIZE_RECV, 0);

			if (nb_bytes == SOCKET_ERROR) {
				MsgPrint(MSG_WARNING, "WARNING: TCP \'recv\' Failed. (Error: %i)\n", ERRORNUM);
				SocketError_close(clientinfo_tcp[sockCliNum].socknum, SOCKET_CLIENT, sockCliNum);
				continue;
			}

			if (!nb_bytes){
				if (shutdown(clientinfo_tcp[sockCliNum].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP \'shutdown\' Failed. (Error: %i)\n", ERRORNUM);
				SocketError_close(clientinfo_tcp[sockCliNum].socknum, SOCKET_CLIENT, sockCliNum);
				continue;
			}
		}
		else //UDP
		{
			nb_bytes = recvfrom(recv_sock, packet, sizeof(packet) - 1, 0, ( struct sockaddr * )&address, &addrlen);

			if (nb_bytes == SOCKET_ERROR)
			{
				char tmpIP[128];
				int netfail;

				netfail = ERRORNUM;
				if (max_msg_level >= MSG_DEBUG || netfail != 10054)
				{
					snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
					MsgPrint(MSG_WARNING, "%-21s ---> %-22s error:%i\n", tmpIP, "WARNING: \'recvfrom\'", netfail);
				}
				else
				{
					snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
					MsgPrint(MSG_NORMAL, "%-21s ---> %-22s error:%i\n", tmpIP, "Server rejected \'ping\'", netfail);
				}

				continue;
			}

			// Ignore abusers
			if (CFG_Ignore_Check(inet_ntoa(address.sin_addr)))
				continue;

		}	//end UDP recv


		///////////////
		//handle packet
		///////////////
		if (!isTCPClient && nb_bytes <= 0) //hypov8 note, error from sending ping after a shutdown. remove??
		{
			server_t       *server;

			if (nb_bytes != SOCKET_ERROR)
			{
				char tmpIP[128];
				snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
				MsgPrint(MSG_DEBUG, "%-21s ---> @%lld returned %d bytes (shutdown)\n", tmpIP, crt_time, nb_bytes);
			}

			server = Sv_GetByAddr(&address, qfalse);
			if (server == NULL)
				continue;

			server->timeout = 0; //remove server
			continue;
		}


		// If we may have to print something, rebuild the peer address buffer
		if (max_msg_level != MSG_NOPRINT)
			snprintf(peer_address, sizeof(peer_address), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

		// We print the packet contents if necessary
		if(max_msg_level >= MSG_DEBUG)
		{
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s @%lld \n", peer_address, "New packet received", crt_time);
			MsgPrint(MSG_DEBUG, "=================================================\n");
			PrintPacket(packet, nb_bytes);
			MsgPrint(MSG_DEBUG, "=================================================\n\n");
		}

		// A few sanity checks
		if (!isTCPClient && nb_bytes < MIN_PACKET_SIZE)		{
			MsgPrint(MSG_WARNING, "WARNING: rejected packet from %s (size = %d bytes)\n", peer_address, nb_bytes);
			continue;
		}

		if(ntohs(address.sin_port) < 1024)		{
			MsgPrint(MSG_WARNING, "WARNING: rejected packet from %s (source port = 0)\n", peer_address);
			continue;
		}

		// Append a '\0' to make the parsing easier
		packet[nb_bytes] = '\0';


		/////////////////
		//Handle Messages
		/////////////////
		if (isTCPClient) //TCP GameSpy
		{
			/* hypov8 packet sent in strange format, replace '\0' with '\\'  */
			if (nb_bytes && packet[0] == '\0')
				replaceNullChar(packet, nb_bytes);

			/* process message */
			if (MSG_HandleMessage_GspyTCP(packet, &address, sockCliNum))
			{
				/* shutdown the connection since we're done */
				if (shutdown(clientinfo_tcp[sockCliNum].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP \'shutdown\' Failed. (Error: %i)", ERRORNUM);

				/* close client temporary socket */
				SocketError_close(clientinfo_tcp[sockCliNum].socknum, SOCKET_CLIENT, sockCliNum);
			}
			//try again?
		}
		else if (isKPQ3) //kingpinq3
		{
			MSG_HandleMessage_KPQ3(packet + 4, &address, recv_sock); //remove YYYY
		}
		else //kingpin (UDP client/server query)
		{
			MSG_HandleMessage_KP1(packet, &address, recv_sock, nb_bytes);
		}
	}

#ifdef _DEBUG
	SV_ClearMem();
	CFG_ClearMem();
#endif

	WEB_Shutdown();

	/* allow enough time to spot error */
	Sys_Sleep(500); //500 milliseconds

	/* close program */
	return 0;
}

static void set_color(int color) 
{
#ifdef WIN32
	if ( !( hStdout == INVALID_HANDLE_VALUE ) )
		SetConsoleTextAttribute(hStdout, (WORD)color);
#else
	// map your color constants to ANSI codes
	switch (color)
	{
		case CONSOLE_COLOR_WHITE:
			fprintf(stdout, "\033[0m"); 
			break;
		case CONSOLE_COLOR_RED:
			fprintf(stdout, "\033[31m");  //red
			break;
		case CONSOLE_COLOR_YELLOW:
			fprintf(stdout, "\033[1;33m"); //bold yellow
			break;
		case CONSOLE_COLOR_BROWN: 
			fprintf(stdout, "\033[33m"); //yellow
			break;
		default:
			break;
	}
#endif
}


// ---------- Public functions ---------- //


/*
====================
MsgPrint

Print a message to screen, depending on its verbose level
====================
*/
int MsgPrint(int msg_level, const char *format, ...)
{
	va_list args;
	int     result;
	int     color = (msg_level & MSG_COLOR_MASK);
	msg_level_t  msg_mode = (msg_level& MSG_LEVEL_MASK);

	// If the message level is above the maximum level, don't print it
	if(msg_mode  > max_msg_level)
		return 0; 

	if (msg_mode == MSG_ERROR || color & MSG_COL_1_RED)
		set_color(CONSOLE_COLOR_RED);
	else if (msg_mode == MSG_WARNING || color & MSG_COL_2_YELLOW)
		set_color(CONSOLE_COLOR_YELLOW);
	else if (color & MSG_COL_3_BROWN)
		set_color(CONSOLE_COLOR_BROWN);
	//SetTextColor(1, 3);
	// SetConsoleTextAttribute();
	

	va_start(args, format);
	result = vprintf(format, args);
	va_end(args);

	fflush(stdout);

	if (msg_mode == MSG_ERROR || msg_mode == MSG_WARNING || color)
		set_color(CONSOLE_COLOR_WHITE);

	return result;
}
