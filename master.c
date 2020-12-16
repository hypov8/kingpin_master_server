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
# include <pwd.h>
# include <unistd.h>
#endif

#include "common.h"
#include "messages.h"
#include "servers.h"


// ---------- Constants ---------- //

// Version of dpmaster
#define VERSION "1.6.09" //hypov8 version

// Default master port
#define DEFAULT_MASTER_PORT 27900 //27900 hypo kingpin
#define DEFAULT_MASTER_PORT_KPQ3 27950 //kpq3 master port
#define DEFAULT_MASTER_PORT_GAMESPY 28900 //GameSpy master port

// Maximum and minimum sizes for a valid packet
#define MIN_PACKET_SIZE 5
#define MAX_PACKET_SIZE_RECV 4096	//hypo ToDo: should we need to check for split packets? gamespy?
									//should not be recieving full server info. 

// web list
#define MAX_WEBLIST	3
#define REFRESH_TIME_WEBLIST	300
#define REFRESH_TIME_DNS		300

#ifndef WIN32
// Default path we use for chroot
# define DEFAULT_JAIL_PATH "/var/empty/"

// User we use by default for dropping super-user privileges
# define DEFAULT_LOW_PRIV_USER "nobody"
#endif


// ---------- Types ---------- //

#ifdef WIN32
typedef int     socklen_t;
#endif


// ---------- Private variables ---------- //

// The port we use
static unsigned short master_port = DEFAULT_MASTER_PORT;
static unsigned short master_port_kpq3 = DEFAULT_MASTER_PORT_KPQ3;
static unsigned short master_port_gs = DEFAULT_MASTER_PORT_GAMESPY;

// Local address we listen on, if any
static const char *listen_name = NULL;
static struct in_addr listen_addr;


#ifndef WIN32
// On UNIX systems, we can run as a daemon
static qboolean daemon_mode = qfalse;

// Path we use for chroot
static const char *jail_path = DEFAULT_JAIL_PATH;

// Low privileges user
static const char *low_priv_user = DEFAULT_LOW_PRIV_USER;
#endif


// ---------- Public variables ---------- //

// The master socket
SOCKET_NET		inSock_udp = INVALID_SOCKET; // listen kp port
SOCKET_NET		inSock_kpq3 = INVALID_SOCKET; //listen kpq3 port
#ifdef USE_ALT_OUTPORT
SOCKET_NET		outSock_udp		 = INVALID_SOCKET; // out kp
SOCKET_NET		outSock_kpq3	 = INVALID_SOCKET; // out kpq3
#endif
SOCKET_NET		inSock_tcp = INVALID_SOCKET; // in tcp
SOCKET_NET		webSock_tcp[MAX_WEBLIST];

#define SOCKET_CLIENT	1
#define SOCKET_WEB		2

// The current time (updated every time we receive a packet)
time_t          crt_time;

//offline/web lists
static qboolean isWebGSPort; //tell web in-sockets to use gamespy or Game protocol
static time_t	ping_dns_time = 0; //add hypo refresh dns
static time_t	ping_timoutSV_time = 0; //add hypo get server updates
static time_t	ping_list_time = 0; // ping offline/web list


//static ip switch
static qboolean isStaticIPHost = qfalse;

// Maximum level for a message to be printed
msg_level_t     max_msg_level = MSG_NORMAL;

// Peer address. We rebuild it every time we receive a new packet
char            peer_address[128];

//hypo console colors
HANDLE hStdout; // , hStdin;
// CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
//



// ---------- Private functions ---------- //

/*
====================
PrintPacket

Print the contents of a packet on stdout
====================
*/
static void PrintPacket(const char *packet, size_t length)
{
	size_t          i;

	// Exceptionally, we use MSG_NOPRINT here because if the function is
	// called, the user probably wants this text to be displayed
	// whatever the maximum message level is.
	MsgPrint(MSG_NOPRINT, "\"");

	for(i = 0; i < length; i++)
	{
		char            c = packet[i];

		if(c == '\\')
			MsgPrint(MSG_NOPRINT, "\\\\");
		else if(c == '\"')
			MsgPrint(MSG_NOPRINT, "\"");
		else if(c >= 32 && (qbyte) c <= 127)
			MsgPrint(MSG_NOPRINT, "%c", c);
		else
			MsgPrint(MSG_NOPRINT, "\\x%02X", c);
	}

	MsgPrint(MSG_NOPRINT, "\" (%u bytes)\n", length);
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
static void SocketError_close(SOCKET_NET socket, int type, int index)
{
	int ret;

#ifdef WIN32
	ret = closesocket(socket);
#else
	ret = close(socket);
#endif

	if (ret)
		MsgPrint(MSG_WARNING, "WARNING. Cant close socket %i \n", socket);

	if (type == SOCKET_CLIENT) {
		clientinfo_tcp[index].socknum = INVALID_SOCKET;
		clientinfo_tcp[index].timeout = 0;
	}
	else if (type == SOCKET_WEB) {
		webSock_tcp[index] = INVALID_SOCKET;
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

	// return qfalse; //hypo todo: enable
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
		MsgPrint(MSG_ERROR, "ERROR: can't initialize winsocks\n");
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
			MsgPrint(MSG_ERROR, "ERROR: can't resolve %s \n", listen_name);
			return qfalse;
		}
		if(itf->h_addrtype != AF_INET)
		{
			MsgPrint(MSG_ERROR, "ERROR: %s is not an IPv4 address \n", listen_name);
			return qfalse;
		}

		memcpy(&listen_addr.s_addr, itf->h_addr, sizeof(listen_addr.s_addr));
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
			MsgPrint(MSG_ERROR, "ERROR: can't get user \"%s\" properties\n", low_priv_user);
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
						master_port = port_num;
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
			 DEFAULT_MAX_NB_SERVERS, DEFAULT_MASTER_PORT, DEFAULT_MASTER_PORT_KPQ3,
#ifndef WIN32
			 DEFAULT_LOW_PRIV_USER,
#endif
			 MSG_DEBUG, MSG_NORMAL, MSG_DEBUG);
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

	MsgPrint(MSG_NORMAL, "-==========================================-\n");

	////////////////////////////////////////////////////////
	// create sockets.
	////////////////////////////////////////////////////////
	/* kp1 */
	inSock_udp = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (inSock_udp < 0)	{
		MsgPrint(MSG_ERROR, "ERROR: inSocket creation failed (%s)\n", strerror(errno));
		return qfalse;
	}
#ifdef USE_ALT_OUTPORT
	outSock_udp = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(outSock_udp < 0)	{
		MsgPrint(MSG_ERROR, "ERROR: outSocket creation failed (%s)\n", strerror(errno));
		return qfalse;
	}
#endif	
	/* kpq3 */
	inSock_kpq3 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (inSock_kpq3 < 0)	{
		MsgPrint(MSG_ERROR, "ERROR: inSocket_kpq3 creation failed (%s)\n", strerror(errno));
		return qfalse;
	}
#ifdef USE_ALT_OUTPORT
	outSock_kpq3 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (outSock_kpq3 < 0)	{
		MsgPrint(MSG_ERROR, "ERROR: outSocket_kpq3 creation failed (%s)\n", strerror(errno));
		return qfalse;
	}
#endif
	////////////////////////////////////////////////////////
	//  Bind it to the ports
	////////////////////////////////////////////////////////
	memset(&address, 0, sizeof(address));

	/* kp1 */
	address.sin_family = AF_INET;
	if(listen_name != NULL)
	{
		MsgPrint(MSG_NORMAL, "Listening on address %s (%s) \n", listen_name, inet_ntoa(listen_addr));
		address.sin_addr.s_addr = listen_addr.s_addr;
	}
	else
		address.sin_addr.s_addr = htonl(INADDR_ANY);

	address.sin_port = htons(master_port);
	if (bind(inSock_udp, (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s) \n", strerror(errno));
		SocketError_close(inSock_udp, 0, 0);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Listening   UDP port %hu -=(  Kingpin  )=- \n", ntohs(address.sin_port));


	/* KPQ3 */
	address.sin_port = htons(master_port_kpq3);
	if (bind(inSock_kpq3, (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s) \n", strerror(errno));
		SocketError_close(inSock_kpq3, 0, 0);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Listening   UDP port %hu -=( KingpinQ3 )=-\n", ntohs(address.sin_port));


#ifdef USE_ALT_OUTPORT //hypo do we need this, may cause issues?
	// UDP OUT KPQ3
	// Deliberately use a different port for outgoing traffic in order
	// to confuse NAT UDP "connection" tracking and thus delist servers
	// hidden by NAT
	address.sin_port = htons(master_port_kpq3 + 1);
	if (bind(outSock_kpq3, (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s)\n", strerror(errno));
		SocketError_close(outSock_kpq3, 0, 0);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Server out  UDP port %hu -=( KingpinQ3 )=-\n", ntohs(address.sin_port));
	//END UDP OUT KPQ3


	// UDP OUT
	// Deliberately use a different port for outgoing traffic in order
	// to confuse NAT UDP "connection" tracking and thus delist servers
	// hidden by NAT
	address.sin_port = htons(master_port + 1);

	if(bind(outSock_udp, (struct sockaddr *)&address, sizeof(address)) != 0)	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s)\n", strerror(errno));
		SocketError_close(outSock_udp, 0, 0);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Server out  UDP port %hu -=(  Kingpin  )=-\n", ntohs(address.sin_port));
	//END UDP OUT
#endif

////////////////////////////////////////////////////////
// listen on TCP for gamespy
////////////////////////////////////////////////////////
	inSock_tcp = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //hypov8
	if (inSock_tcp == INVALID_SOCKET)	{
		MsgPrint(MSG_WARNING, "Server: Error at socket(): (%s)\n", strerror(errno));
		SocketError_close(inSock_tcp, 0, 0);
		return qfalse;
	}

	//sockaddr_in service;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(master_port_gs); // master_port + 1000); //hypov8 todo: add startup cmd switch?

	if (bind(inSock_tcp, (struct sockaddr *)&address, sizeof(address)) != 0)	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s) \n", strerror(errno));
		SocketError_close(inSock_tcp, 0, 0);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Listening   TCP port %hu -=(  Gamespy  )=- \n", ntohs(address.sin_port));

	if (listen(inSock_tcp, 10) == SOCKET_ERROR) {//hypo todo: test. is 10 enough?
		MsgPrint(MSG_ERROR, "listen(): Error listening on socket (%s). \n", strerror(errno));
		SocketError_close(inSock_tcp, 0, 0);
		return qfalse;
	}
///////////////
//end tcp Gamespy
///////////////

// increase socket buffer for big web lists
	{
		//getsockopt(inSock_udp, )
		int iResult = 0;

		int bOptVal = 2048*256;
		int bOptLen = sizeof(int);

		int iOptVal = 0;
		int iOptLen = sizeof(int);
		//bOptVal = TRUE;

		//						sock		int			int				char		int
		iResult = setsockopt(inSock_udp, SOL_SOCKET, SO_RCVBUF, (char *)&bOptVal, bOptLen);
		if (iResult !=SOCKET_ERROR)
		{
			iResult = getsockopt(inSock_udp, SOL_SOCKET, SO_RCVBUF, (char *)&iOptVal, &iOptLen);
			if (iResult !=SOCKET_ERROR)
				MsgPrint(MSG_NORMAL, "recv Buf:   %ld \n", iOptVal);
				
		}

		iResult = setsockopt(inSock_udp, SOL_SOCKET, SO_SNDBUF, (char *)&bOptVal, bOptLen);
		if (iResult != SOCKET_ERROR)
		{
			iResult = getsockopt(inSock_udp, SOL_SOCKET, SO_SNDBUF, (char *)&iOptVal, &iOptLen);
			if (iResult !=SOCKET_ERROR)		
			MsgPrint(MSG_NORMAL, "rend Buf:   %ld \n", iOptVal);
		}

		//iResult = getsockopt(inSock_udp, SOL_SOCKET, SO_RCVBUF, (char *)&iOptVal, &iOptLen);
		//wprintf(L"SO_KEEPALIVE Value: %ld\n", iOptVal);

	}

	MsgPrint(MSG_NORMAL, "-==========================================-\n");
	MsgPrint(MSG_NORMAL, "listen() is OK, I'm waiting for connections...\n");


	//hypo console colors
#ifdef WIN32
	//system("COLOR 07");
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
#endif

	return qtrue;
} 


static qboolean exitNow = qfalse;

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
#define PORT_LENGTH 6
#define ADDRESS_LENGTH 16
#define ADDRESS_LENGTHMAX 253 //16+16+1 //hypov8 ip+ip+= //changed.. dns lengths.....
static const char *ipIgnoreFile_Name =	"ip_ignore.txt";
static const char *ipConvertFile_Name =	"ip_rename.txt"; //hypov8 ip rename
static const char *ipOfflineFile_Name =	"ip_offline.txt"; //hypov8 ip rename
static const char *webListFile_gp_Name = "ip_weblist.txt";
static const char *webListFile_gs_Name = "ip_weblist_gs.txt";

typedef struct
{
	char            address[ADDRESS_LENGTH];	// Dotted quad
} ignoreAddress_t;


typedef struct
{
	char            address[ADDRESS_LENGTHMAX];	// hypo dns
	char			port[PORT_LENGTH];
} offlineList_t;

typedef struct
{
	char            address[ADDRESS_LENGTHMAX];	// hypo dns
	char			port[PORT_LENGTH];
	char			file[ADDRESS_LENGTHMAX];
} webList_t;


#define PARSE_INTERVAL		60	// seconds

static time_t   lastParseTime = 0;
static int      numIgnoreAddresses = 0;
static ignoreAddress_t *ignoreAddresses = NULL;
static ignoreAddress_t *ipAddresses = NULL; //hypov8 ip rename

//offline list
static time_t   lastParseTimeOffline = 0;
static int      numOfflineList = 0;
static offlineList_t *offlineList_ptr = NULL;

//web list
static int     numwebList = 0; 
static offlineList_t *webList_ptr = NULL;
static webList_t	webString[3];

/*
====================
MAST_parseIgnoreAddress

will always load file when a new ip request
====================
*/
static qboolean MAST_parseIgnoreAddress(void)
{
	int             numAllocIgnoreAddresses = 1;
	FILE           *f = NULL;
	int             i;
	qboolean		skipLine;
	time_t			timediff;

	timediff = crt_time - lastParseTime;

	// Only reparse periodically
	if (timediff < PARSE_INTERVAL)
		return qtrue;

	lastParseTime = time(NULL);

	// Free existing list
	if(ignoreAddresses != NULL)
	{
		free(ignoreAddresses);
		ignoreAddresses = NULL;
	}

	numIgnoreAddresses = 0;
	ignoreAddresses = malloc(sizeof(ignoreAddress_t) * numAllocIgnoreAddresses);

	// Alloc failed, fail parsing
	if(ignoreAddresses == NULL)
		return qfalse;
	
	MsgPrint(MSG_DEBUG, "Loading... %s\n", ipIgnoreFile_Name);
	f = fopen(ipIgnoreFile_Name, "r");
	if(!f)
	{
		free(ignoreAddresses);
		ignoreAddresses = NULL;
		return qfalse;
	}

	while(!feof(f))
	{
		char            c;
		char            buffer[ADDRESS_LENGTH];

		i = 0;

		// Skip whitespace
		do
		{
			c = (char)fgetc(f);
		}
		while(c != EOF && isspace(c));

		if (c != EOF)
		{
			memset(buffer, 0, sizeof(buffer)); //hypov8 reset buffer length to zero
			skipLine = qfalse; //add hypo allow comments
			do
			{
				if (i >= ADDRESS_LENGTH)
				{
					buffer[i - 1] = '\0';
					break;
				}

				buffer[i] = c;

				if (isspace(c))
				{
					buffer[i] = '\0';
					break;
				}

				if (i == 0 && (buffer[0] == '/'))
				{
					char tmpBuff[256];
					buffer[i] = '\0';
					fgets(tmpBuff, 256, f); //goto next line in file
					skipLine = qtrue; //comment line
					break;
				}

				i++;
			} while ((c = (char)fgetc(f)) != EOF);
			if (!skipLine)
			{
				strcpy(ignoreAddresses[numIgnoreAddresses].address, buffer);

				numIgnoreAddresses++;

				// Make list bigger
				if (numIgnoreAddresses >= numAllocIgnoreAddresses)
				{
					ignoreAddress_t *new;

					numAllocIgnoreAddresses *= 2;
					new = realloc(ignoreAddresses, sizeof(ignoreAddress_t) * numAllocIgnoreAddresses);

					// Alloc failed, fail parsing
					if (new == NULL)
					{
						fclose(f);
						free(ignoreAddresses);
						ignoreAddresses = NULL;
						return qfalse;
					}

					ignoreAddresses = new;
				}
			}
		}
	}

	fclose(f);

	return qtrue;
}


/*
====================
MAST_parseOfflineList

hypo offline list to ping
====================
*/
static qboolean MAST_parseOfflineList(void)//char* webText
{
	int			numAllocOfflineList = 1;
	FILE		*f = NULL;
	char		s[ADDRESS_LENGTHMAX];


	if (offlineList_ptr != NULL)
		MsgPrint(MSG_WARNING, "WARNING: OfflineList pointer not free\n");

	MsgPrint(MSG_DEBUG, "Loading... %s\n", ipOfflineFile_Name);
	f = fopen(ipOfflineFile_Name, "r");
	if (!f)	{
		return qfalse;
	}

	//reset list count
	numOfflineList = 0;

	//allocate memory
	offlineList_ptr = malloc(sizeof(offlineList_t) * numAllocOfflineList);
	if (offlineList_ptr == NULL) {
		return qfalse;
	}

	//loop through each line
	while (fgets(s, ADDRESS_LENGTHMAX, f) != NULL && !feof(f))
	{
		char *port, j;

		// Skip comment lines
		if (s[0] == '/')
			continue;

		//check for port
		port = strstr(s, ":");
		if (port == NULL)	
		{
			//hypov8 todo error message??
			continue;
		}
		*port++ = '\0';
		port[7] = '\0';
		for (j = 0; j < 7; j++) 
		{
			if (port[j] == '\n') {
				port[j] = '\0';
				break;
			}
		}
		//copy port and ip
		strcpy(offlineList_ptr[numOfflineList].port, port);
		strcpy(offlineList_ptr[numOfflineList].address, s);
		numOfflineList++;

		// Make list bigger
		if (numOfflineList >= numAllocOfflineList)
		{
			offlineList_t *reDefList;

			numAllocOfflineList *= 2;
			reDefList = realloc(offlineList_ptr, sizeof(offlineList_t) * numAllocOfflineList);

			// Alloc failed, fail parsing
			if (reDefList == NULL)
			{
				fclose(f);
				free(offlineList_ptr);
				offlineList_ptr = NULL;
				return qfalse;
			}
			else
				offlineList_ptr = reDefList;
		}
	}

	fclose(f);

	return qtrue;
}


static qboolean MAST_parseWebListFile(qboolean isGSPorts)//char* webText
{
	int		len,count = 0;
	FILE	*file = NULL;
	char	*s, line[1024];
	char	*tmpPort, *tmpFile;

	memset(&webString, 0, sizeof(webString));

	if ( isGSPorts ) {
		MsgPrint(MSG_DEBUG, "Loading... %s\n", webListFile_gs_Name);
		file = fopen(webListFile_gs_Name, "r");
	}
	else {
		MsgPrint(MSG_DEBUG, "Loading... %s\n", webListFile_gp_Name);
		file = fopen(webListFile_gp_Name, "r");
	}

	if(!file)
		return qfalse;

	
	while (fgets(line, 1024, file)&& count < MAX_WEBLIST)
	{
		int has_port = 0;

		s = line;
		// skip initial white space chars
		while (*s && isspace(*s))
			s++;

		// skip emtpy lines and comments
		if (!(*s) || *s == '#' || !strncmp(s, "//", 2))
			continue;

		// remove trailing white space chars
		len = strlen(s);
		while (len > 0 && isspace(s[len - 1]))
			s[--len] = '\0';

		//nothing left to read
		if (!s[0])
			continue;

		//has a port?
		tmpPort = strstr(s, ":");
		if (tmpPort != NULL)
		{
			tmpPort++;
			has_port = 1;
		}

		//has a file path
		tmpFile = strstr(s, "/");
		if (tmpFile == NULL)
			continue;

		if (has_port)
		{
			int pLen = strlen(tmpPort);
			int fLen = strlen(tmpFile);
			int dnsLen = len - pLen-1; //dns address
			int plen2 = pLen - fLen;
			snprintf(webString[count].port, plen2, "%s", tmpPort);	
			snprintf(webString[count].address, dnsLen, "%s", s);
			snprintf(webString[count].file, fLen, "%s", tmpFile);
		}
		else //no port
		{
			int fLen = strlen(tmpFile);
			int dnsLen = len - fLen; //dns address
			snprintf(webString[count].address, dnsLen, "%s", s);
			snprintf(webString[count].file, fLen, "%s", tmpFile);
		}	
		count++;
	}		

	fclose(file);

	return qtrue;
}

static qboolean MAST_parseWebListIPs(const char* webText)//
{
	int             numAllocWebList = 1;
	int             i, j, k;
	qboolean		Error =1;
	char* split_request;


	// Free existing list
	if (webList_ptr != NULL)
		MsgPrint(MSG_WARNING, "WARNING: OfflineList pointer not free\n");


	numwebList = 0;
	webList_ptr = malloc(sizeof(offlineList_t) * numAllocWebList);

	// Alloc failed, fail parsing
	if (webList_ptr == NULL)
		return qfalse;


	split_request = strtok((char*)webText, "\r\n");
	while (split_request != NULL)
	{
		char c;

		c = split_request[0];
		if (c)
		{
			if (strstr(split_request, "Content-Type: text")!=NULL )
			{
				split_request = strtok(NULL, "\r\n");
				Error = 0;
				break;
			}
			//error
			if (strstr(split_request, "404 Not Found")!=NULL )
				break;

			split_request = strtok(NULL, "\r\n");
			continue;
		}
		break; //error. end of line
	}


	if (!Error)
	{
		char            c;
		char            buffer[ADDRESS_LENGTHMAX];
		char            bufferPort[PORT_LENGTH];
		qboolean		port;

		while (split_request != NULL)
		{
			i = 0;
			j = 0;
			k = 0;

			// Skip whitespace
			c = split_request[i];
			if (!c || isspace(c) || c == '\\'||c == '/')
			{
				split_request = strtok(NULL, "\r\n");
				continue;
			}

			memset(buffer, 0, sizeof(buffer)); //hypov8 reset buffer length to zero
			memset(bufferPort, 0, sizeof(bufferPort)); //hypov8 reset buffer length to zero
			port = qfalse;
			do
			{
				if (i >= ADDRESS_LENGTHMAX)	{
					buffer[i - 1] = '\0';
					break;
				}

				if (c == ':'){
					buffer[i] = '\0';
					port = qtrue;
					i++;
					continue;
				}

				if (!port)	{
					buffer[i] = c;

					if (isspace(c))	{
						buffer[i] = '\0';
						break;
					}
				}
				else
				{
					bufferPort[j] = c;

					if (isspace(c))	{
						bufferPort[j] = '\0';
						break;
					}

					j++;
				}

				i++;
			} while ((c = split_request[i])!=0 && (c != '\r' || c != '\n') );


			strcpy(webList_ptr[numwebList].address, buffer);
			strcpy(webList_ptr[numwebList].port, bufferPort);

			numwebList++;

			// Make list bigger
			if (numwebList >= numAllocWebList)
			{
				offlineList_t *new;

				numAllocWebList *= 2;
				new = realloc(webList_ptr, sizeof(offlineList_t) * numAllocWebList);

				// Alloc failed, fail parsing
				if (new == NULL)
				{
					free(webList_ptr);
					webList_ptr = NULL;
					return qfalse;
				}

				webList_ptr = new;
			}

			split_request = strtok(NULL, "\r\n");
		} //while (split_request != NULL);

	} 
	else
		return qfalse;

	return qtrue;

}


/*
====================
ignoreAddress

Check whether or not to ignore a specific address
====================
*/
static qboolean ignoreAddress(const char *address)
{
	int             i;

	if(!MAST_parseIgnoreAddress())
	{
		// Couldn't parse, allow the address
		return qfalse;
	}

	for(i = 0; i < numIgnoreAddresses; i++)
	{
		if(strcmp(address, ignoreAddresses[i].address) == 0)
			break;
	}

	// It matched
	if (i < numIgnoreAddresses){
		MsgPrint(MSG_DEBUG, "WARNING: web address ingnored \n");
		return qtrue;
	}

	return qfalse;
}


/*
====================
MAST_Check_OfflineList

Load offline list
====================
*/
static void MAST_Check_OfflineList()
{
	int             i;

	if (ping_list_time != 0) // let weblist load next
		ping_list_time = crt_time + REFRESH_TIME_WEBLIST;

	MsgPrint(MSG_DEBUG, "Processing Offline List\n");

	if (!MAST_parseOfflineList())
	{	// Couldn't parse, offline list
		MsgPrint(MSG_DEBUG, "OFFLINELIST: Failed\n");
		return;
	}
	else
	{
		for ( i = 0; i < numOfflineList; i++ )
		{
			Sv_PingOfflineList(offlineList_ptr[ i ].address, offlineList_ptr[ i ].port, qfalse);
		}

		//clear old memory
		free(offlineList_ptr);
		offlineList_ptr = NULL;
	}
}


/*
====================
MAST_Check_WebList

Load WebList
====================
*/
static void MAST_Check_WebList(qboolean isGS)
{
	int             i, bufChars;
	char recvbuf[MAX_PACKET_SIZE_RECV];
	char recvbufAll[MAX_PACKET_SIZE_RECV * 3];
	struct sockaddr_in	tmpServerAddress;
	char message[MAX_PACKET_SIZE_RECV];
	char message1[] = "GET ";
	char message2[] = " HTTP/1.1\r\nHost: ";
	char message3[]="\r\n\r\n";
	char* webListFileNameString;

	//set time for next refresh
	if (ping_list_time == 0)
		ping_list_time = crt_time + 20; //get weblist GS sooner 1st time
	else
		ping_list_time = crt_time + REFRESH_TIME_WEBLIST;

	if ( isGS )
	{
		MsgPrint(MSG_DEBUG, "Processing WebList: Gamespy\n");
		webListFileNameString = ( char* ) webListFile_gs_Name;
		isWebGSPort = qtrue; //set responce type
	}
	else
	{
		MsgPrint(MSG_DEBUG, "Processing WebList: Gameport\n");
		webListFileNameString = ( char* ) webListFile_gp_Name;
		isWebGSPort = qfalse; //set responce type
	}

	//reset sockets
	for(i = 0; i < MAX_WEBLIST; i++)
	{
		//did not disconect properly
		if (webSock_tcp[i] != INVALID_SOCKET)
			SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
	}


	//open weblist.txt. if valid, send packet
	if (MAST_parseWebListFile(isGS))
	{
		bufChars = 0;
		i = 0;
		//loop through max web list. send inital contact
		for (i = 0; i < MAX_WEBLIST; i++)
		{
			if (webString[i].address[0] != '\0')
			{
				memset(recvbuf, 0, sizeof(recvbuf));
				memset(recvbufAll, 0, sizeof(recvbufAll));
				memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));

				//validate address
				if (!Sv_ResolveAddr(webString[i].address, &tmpServerAddress))
					continue;

				tmpServerAddress.sin_port = htons((u_short)atoi("80"));
				//use port if any
				if (webString[i].port[0] != '\0')
					tmpServerAddress.sin_port = htons((u_short)atoi(webString[i].port));

					


				webSock_tcp[i] = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //hypov8
				if (webSock_tcp[i] == INVALID_SOCKET)	{
					MsgPrint(MSG_WARNING, "WARNING: Socket() failed for weblist (error: %d)\n", ERRORNUM);
					SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
					continue;
				}

				if (connect(webSock_tcp[i], (struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)) == SOCKET_ERROR){
					MsgPrint(MSG_WARNING, "WARNING: Connect() failed. ( %s index: %i error: %d ) \n",
						webListFileNameString, i + 1, ERRORNUM);
					SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
					continue;
				}

				memset(message, 0, sizeof(message));
				strcat(message, message1);				//""GET "
				strcat(message, webString[i].file);		//"list.htm"
				strcat(message, message2);				//" HTTP/1.1\r\nHost: "
				strcat(message, webString[i].address);	//www.123.com
				strcat(message, message3);			//hypov8 todo: do we need address again?

				//ioctlsocket(webSock_tcp[i], FIONBIO, &iMode);

				//Send some data
				//message = "GET /?st=1 HTTP/1.1\r\nHost: www.msn.com\r\n\r\n";
				if (send(webSock_tcp[i], message, strlen(message), 0) == SOCKET_ERROR)	{
					MsgPrint(MSG_WARNING, "WARNING: Send() failed. ( %s index: %i error: %d ) \n",
						webListFileNameString, i + 1, ERRORNUM);
					SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
					continue;
				}

				MsgPrint(MSG_DEBUG, "WEBLIST: 'send' completed ok. ( %s index: %i )\n", webListFileNameString, i + 1);
			}
		}
	}
}


/*
====================
MAST_WebList_Responce

respopnce from WebList
====================
*/
static void MAST_WebList_Responce(int recieveSock)
{
	int		i, bufChars,iResult;
	char	recvbuf[MAX_PACKET_SIZE_RECV+1];
	char	recvbufAll[MAX_PACKET_SIZE_RECV * 3+1];
	int		recvbufLen = MAX_PACKET_SIZE_RECV;
	bufChars = 0;
	i = 0;

	memset(recvbuf, 0, sizeof(recvbuf));
	memset(recvbufAll, 0, sizeof(recvbufAll));

	//hypo todo: will sit here waiting for next packet.. 100+ servers set global?
	do {
		iResult = recv(webSock_tcp[recieveSock], recvbuf, recvbufLen, 0);
		if (iResult > 0){
			strncat(recvbufAll, recvbuf, iResult);
			//strcat(recvbufAll, recvbuf);
			MsgPrint(MSG_DEBUG, "WEBLIST: Bytes received: %d\n", iResult);
		}
		else if (iResult == SOCKET_ERROR){
			MsgPrint(MSG_WARNING, "WARNING: WEBLIST 'recv' Failed. (Error: %d)\n", ERRORNUM);
			break;
		}

		if (strstr(recvbuf, "404 Not Found") != NULL){
			MsgPrint(MSG_WARNING, "ERROR: 404 Not Found. Check WebList.txt\n");
			break;
		}

		if (iResult > 0 && iResult < recvbufLen){
			MsgPrint(MSG_DEBUG, "WEBLIST: Finished. Bytes received: %i\n", iResult);
			break;
		}

		memset(recvbuf, 0, sizeof(recvbuf));
		i++;
	} while (iResult > 0 &&  i < 3); //3 gets then timeout


	// shutdown the connection since no more data will be sent
	if (shutdown(webSock_tcp[recieveSock], TCP_SHUTBOTH) == SOCKET_ERROR){
		MsgPrint(MSG_WARNING, "WARNING: WEBLIST 'shutdown' Failed. (Error: %d)\n", ERRORNUM);
		SocketError_close(webSock_tcp[recieveSock], SOCKET_WEB, recieveSock);
		return;
	}
	SocketError_close(webSock_tcp[recieveSock], SOCKET_WEB, recieveSock);


	if (MAST_parseWebListIPs(recvbufAll))
	{	
		if (isWebGSPort)
			MsgPrint(MSG_NORMAL, "WEBLIST: Sending '\\status\\' to %d servers\n", numwebList);
		else
			MsgPrint(MSG_NORMAL, "WEBLIST: Sending 'yyyystatus' to %d servers\n", numwebList);

		for (i = 0; i < numwebList; i++)
		{
			if (isWebGSPort)
				Sv_PingOfflineList(webList_ptr[i].address, webList_ptr[i].port, qtrue);
			else
				Sv_PingOfflineList(webList_ptr[i].address, webList_ptr[i].port, qfalse);
		}

		free(webList_ptr);
		webList_ptr = NULL;
	}
	else
	{
		// Error, couldn't parse web reply.
		MsgPrint(MSG_WARNING, "WEBLIST: Invalid server list recieved \n");
		return;
	}


}


/*
====================
MAST_parseIPConversionFile

file loaded at start
====================
*/
qboolean MAST_parseIPConversionFile(void)
{
	FILE           *f = NULL;
	int             i;
	qboolean		skipLine;

	MsgPrint(MSG_DEBUG, "Loading... %s\n", ipConvertFile_Name);
	f = fopen(ipConvertFile_Name, "r");
	if (!f)
	{
		MsgPrint(MSG_WARNING, "WARNING: Cound not open 'ip_rename.txt' \n");
		free(ipAddresses);
		ipAddresses = NULL;
		return qfalse;
	}

	while (!feof(f))
	{
		char            c;
		char            buffer[ADDRESS_LENGTHMAX];

		i = 0;

		// Skip whitespace
		do
		{
			c = (char)fgetc(f);
		} while (c != EOF && isspace(c));

		if (c != EOF)
		{
			memset(buffer, 0, sizeof(buffer)); //hypov8 reset buffer to zero
			skipLine = qfalse; //add hypo allow comments
			do
			{
				if (i >= ADDRESS_LENGTHMAX)
				{
					buffer[i - 1] = '\0';
					break;
				}

				buffer[i] = c;

				if (isspace(c))
				{
					buffer[i] = '\0';
					break;
				}

				if (i == 0 && (buffer[0] == '/'))
				{
					char tmpBuff[256];
					buffer[i] = '\0';
					fgets(tmpBuff, 256, f); //goto next line in file
					skipLine = qtrue; //comment line
					break;
				}

				i++;
			} while ((c = (char)fgetc(f)) != EOF);

			//buffer[i] = '\0';
			if (!skipLine)
				Sv_Add_unResolvedAddressMapping(buffer); //hypov8 add ip
		}
	}

	fclose(f);

	return qtrue;
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

	for (i = 0; i <= packet_len; i++)
	{
		if (i == packet_len) //hypov8 note +1 ok?
			packet[ i ] = '\0';
		else if (packet[i] == '\0')
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
	static short listIdx = 1; //get gameport 1st
	int i;

	//timeout clients
	for (i = 0; i < MAX_CLIENTS; i++)	
	{
		if ( clientinfo_tcp[i].socknum != INVALID_SOCKET &&
			clientinfo_tcp[i].timeout > 0 && 
			clientinfo_tcp[i].timeout < crt_time) //add extra time?
		{
			char tmpIP[128];
			snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(clientinfo_tcp[i].tmpClientAddress.sin_addr), 
														ntohs(clientinfo_tcp[i].tmpClientAddress.sin_port));
			MsgPrint(MSG_WARNING, "%-21s ---- %-22s Removed \n", tmpIP, "Client timed out.");
			SocketError_close(clientinfo_tcp[i].socknum, SOCKET_CLIENT, i);
		}
	}

	// hypo update servers about to time out. when no activity
	if (ping_timoutSV_time < crt_time)	
	{
		Sv_PingTimeOut_GamePort();
		ping_timoutSV_time = crt_time + 20; //check every 20 secs
	}

#if 1 //debug
	//MAST_Check_OfflineList();
#endif
	//get servers from txt files
	if (ping_list_time < crt_time)
	{
		switch (listIdx)
		{
		default:
		case 0:
				MAST_Check_OfflineList();
			break;
		case 1:
				MAST_Check_WebList(qfalse);//game port
			break;
		case 2:
				MAST_Check_WebList(qtrue);//GS port
			break;
		}

		listIdx += 1;
		if (listIdx >= 3)
			listIdx = 0;
	}

	// hypov8 try resolve dns names every 5 min(dynamic ip's)
	if (!isStaticIPHost && ping_dns_time < crt_time)	
	{	
		Sv_ResolveAddressMappings();
		ping_dns_time = crt_time + REFRESH_TIME_DNS; //5 min
	}
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

/*
====================
main

Main function
====================
*/
int main(int argc, const char *argv[])
{
	struct sockaddr_in address;
	int				addrlen = sizeof(address);
	int             nb_bytes;
	SOCKET_NET      recv_sock, fd_sok;
	char            packet[MAX_PACKET_SIZE_RECV + 1];	// "+ 1" because we append a '\0'
	qboolean        valid_options;
	fd_set          rfds;
	struct timeval  tv;
	qboolean		isTCP, isKPQ3, isClient, isWebList;
	int				iSendResult;
	int				i;
	int				sockCliNum, sockWebNum;

	//hypov8 initialize address
	address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_ANY);

	signal(SIGINT, cleanUp);
	signal(SIGTERM, cleanUp);

	// Get the options from the command line
	valid_options = ParseCommandLine(argc, argv);

	MsgPrint(MSG_NORMAL, "Kingpin master (version " VERSION " " __DATE__ " " __TIME__ ")\n");

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
		MsgPrint(MSG_ERROR, "\n  --==  SHUTTING DOWN  ==--\n");
		Sys_Sleep(5000); //5 seconds
		return EXIT_FAILURE;
	}

	MsgPrint(MSG_NORMAL, "\n");

	//initialise all client_socket[] to 0 so not checked
	for (i = 0; i < MAX_CLIENTS; i++)
	{
		clientinfo_tcp[i].socknum = INVALID_SOCKET;
	}
	for (i = 0; i < MAX_WEBLIST; i++)
	{
		webSock_tcp[i] = INVALID_SOCKET;
	}

	//inital startup. process offline/web lists
	MAST_Check_OfflineList(); //must be first then weblist
	MAST_Check_WebList(qtrue);//GS port
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
			fd_sok = outSock;
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
		//add child web sockets to set 
		for (i = 0; i < MAX_WEBLIST; i++)
		{
			if (webSock_tcp[i] != INVALID_SOCKET) {
				FD_SET(webSock_tcp[i], &rfds);
				if (webSock_tcp[i] > fd_sok)
					fd_sok = webSock_tcp[i];
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
				MsgPrint(MSG_WARNING, "WARNING: TCP 'select' socket Failed. (Error: %d) \n", ERRORNUM);

			//run event's when there is nothing else to do
			MAST_GlobalTimedEvent();

			Sys_Sleep(100); //100 milliseconds
			continue;
		}

		isTCP = 0;
		isClient = 0;
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
		else if (webSock_tcp[0] != INVALID_SOCKET &&
			FD_ISSET(webSock_tcp[0], &rfds))	{
			isWebList = 1;
			sockWebNum = 0;
		}
		else if (webSock_tcp[1] != INVALID_SOCKET &&
			FD_ISSET(webSock_tcp[1], &rfds))	{
			isWebList = 1;
			sockWebNum = 1;
		}
		else if (webSock_tcp[2] != INVALID_SOCKET &&
			FD_ISSET(webSock_tcp[2], &rfds))	{
			isWebList = 1;
			sockWebNum = 2;
		}
		else
		{
			for (i = 0; i < MAX_CLIENTS; i++)
			{
				if (clientinfo_tcp[i].socknum != INVALID_SOCKET &&
					FD_ISSET(clientinfo_tcp[i].socknum, &rfds))
				{
					isClient = 1;
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
					MsgPrint(MSG_WARNING, "WARNING: TCP 'shutdown' Failed. (Error: %i)", ERRORNUM);
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
			if (ignoreAddress(inet_ntoa(address.sin_addr)))	{
				char tmpIP[128];
				snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
				MsgPrint(MSG_WARNING, "%-21s ---> CLIENT: in ignore list \n", tmpIP);
				SocketError_close(clientinfo_tcp[cliID].socknum, SOCKET_CLIENT, cliID);
				continue;
			}
			// prevent flooding
			if (FloodIpStoreReject(&address))	{
				char tmpIP[128];
				snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
				MsgPrint(MSG_WARNING, "%-21s ---> FLOOD: Client Rejected\n", tmpIP);
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
		else if (isClient) //existing conection, get packet
		{
			nb_bytes = recv(clientinfo_tcp[sockCliNum].socknum, packet, MAX_PACKET_SIZE_RECV, 0);

			if (nb_bytes == SOCKET_ERROR) {
				MsgPrint(MSG_WARNING, "WARNING: TCP 'recv' Failed. (Error: %i)\n", ERRORNUM);
				SocketError_close(clientinfo_tcp[sockCliNum].socknum, SOCKET_CLIENT, sockCliNum);
				continue;
			}

			if (!nb_bytes){
				if (shutdown(clientinfo_tcp[sockCliNum].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP 'shutdown Failed. (Error: %i)\n", ERRORNUM);
				SocketError_close(clientinfo_tcp[sockCliNum].socknum, SOCKET_CLIENT, sockCliNum);
				continue;
			}
		}
		else if (isWebList)
		{
			MsgPrint(MSG_DEBUG, "WEBLIST: Responce \n");
			MAST_WebList_Responce(sockWebNum);
			continue;
		}
		else //end TCP
			///////////
		{	//start UDP
			nb_bytes = recvfrom(recv_sock, packet, sizeof(packet) - 1, 0, ( struct sockaddr * )&address, &addrlen);

			if (nb_bytes == SOCKET_ERROR)
			{
				char tmpIP[128];
				int netfail;

				netfail = ERRORNUM;
				if (max_msg_level >= MSG_DEBUG || netfail != 10054)
				{
					snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
					MsgPrint(MSG_WARNING, "%-21s ---> %-22s error:%i\n", tmpIP, "WARNING: 'recvfrom'", netfail);
				}
				else
				{
					snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
					MsgPrint(MSG_NORMAL, "%-21s ---> %-22s error:%i\n", tmpIP, "Server rejected 'ping'", netfail);
				}

				continue;
			}

			// Ignore abusers
			if (ignoreAddress(inet_ntoa(address.sin_addr)))
				continue;

		}	//end UDP recv


		///////////////
		//handle packet
		///////////////
		if (!isClient && nb_bytes <= 0) //hypov8 note, error from sending ping after a shutdown. remove??
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

			server->timeout = crt_time /*+ (5*1000)*/; //remove server??
			continue;
		}


		// If we may have to print something, rebuild the peer address buffer
		if (max_msg_level != MSG_NOPRINT)
			snprintf(peer_address, sizeof(peer_address), "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));


		// We print the packet contents if necessary
		if(max_msg_level >= MSG_DEBUG)
		{
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s @%lld \n", peer_address, "New packet received", crt_time);
			MsgPrint(MSG_DEBUG, "=================================================\n", peer_address);
			PrintPacket(packet, nb_bytes);
			MsgPrint(MSG_DEBUG, "=================================================\n\n", peer_address);
		}

		// A few sanity checks
		if (!isClient && nb_bytes < MIN_PACKET_SIZE)		{
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
		if (isClient) //TCP GameSpy
		{
			/* hypov8 packet sent in strange format, replace '\0' with '\\'  */
			if (nb_bytes && packet[0] == '\0')
				replaceNullChar(packet, nb_bytes);

			/* process message */
			if (MSG_HandleMessage_GspyTCP(packet, &address, sockCliNum))
			{
				/* shutdown the connection since we're done */
				if (shutdown(clientinfo_tcp[sockCliNum].socknum, TCP_SHUTBOTH) == SOCKET_ERROR)
					MsgPrint(MSG_WARNING, "WARNING: TCP 'shutdown' Failed. (Error: %i)", ERRORNUM);

				/* close client temporary socket */
				SocketError_close(clientinfo_tcp[sockCliNum].socknum, SOCKET_CLIENT, sockCliNum);
			}
			//try again?
		}
		else if (isKPQ3) //kingpinq3
		{
			MSG_HandleMessage_KPQ3(packet + 4, &address, recv_sock); //remove YYYY
		}
		else //kingpin
		{
			MSG_HandleMessage_KP1(packet, &address, recv_sock, nb_bytes);
		}
	}


	/* allow enough time to spot error */
	Sys_Sleep(500); //500 milliseconds

	/* close program */
	return 0;
}


// ---------- Public functions ---------- //


/*
====================
MsgPrint

Print a message to screen, depending on its verbose level
====================
*/
int MsgPrint(msg_level_t msg_level, const char *format, ...)
{
	va_list         args;
	int             result;

	// If the message level is above the maximum level, don't print it
	if(msg_level > max_msg_level)
		return 0; 




#ifdef WIN32
	if (!(hStdout == INVALID_HANDLE_VALUE))
		if (msg_level==1)
			SetConsoleTextAttribute(hStdout, FOREGROUND_RED /*| FOREGROUND_INTENSITY*/);
		else if (msg_level == 2)
			SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_RED /*| FOREGROUND_INTENSITY*/);
	//SetTextColor(1, 3);
	// SetConsoleTextAttribute();
#endif

	va_start(args, format);
	result = vprintf(format, args);
	va_end(args);

	fflush(stdout);

#ifdef WIN32
	//reset to white
	if (!(hStdout == INVALID_HANDLE_VALUE))
		if (msg_level==1)
			SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE);
		else if (msg_level == 2)
			SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_RED |FOREGROUND_BLUE);
#endif

	return result;
}
