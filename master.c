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
#define VERSION "1.6.01" //hypo

// Default master port
#define DEFAULT_MASTER_PORT 27900 //28900 hypo kp1
#define DEFAULT_MASTER_PORT_KPQ3 27950 //kpq3 master port
#define DEFAULT_MASTER_PORT_GAMESPY 28900 //GameSpy master port

// Maximum and minimum sizes for a valid packet
#define MAX_PACKET_SIZE 2048 //hypo ToDo: should we need to check for split packets? gamespy?
#define MIN_PACKET_SIZE 5

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
SOCKET_NET		inSock = INVALID_SOCKET; // listen kp port
SOCKET_NET		inSock_kpq3 = INVALID_SOCKET; //listen kpq3 port
#ifdef USE_ALT_OUTPORT
SOCKET_NET		outSock			 = INVALID_SOCKET; // out kp
SOCKET_NET		outSock_kpq3	 = INVALID_SOCKET; // out kpq3
#endif
SOCKET_NET		inSock_tcp = INVALID_SOCKET; // in tcp
SOCKET_NET		tmpClientOut_tcp = INVALID_SOCKET; //used for gamespylite tempory client connection

//SOCKET_NET A_Sockets[4];
// A_Sockets[0] = inSock;

// The current time (updated every time we receive a packet)
time_t          crt_time;
time_t			last_dns_time =0; //add hypo refresh dns

//static ip switch
qboolean isStaticIPHost = qfalse;

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
====================
*/
static void SocketError_close(SOCKET_NET old_socket)
{
#ifdef WIN32
	closesocket(old_socket);
#else
	close(old_socket);
#endif

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
			MsgPrint(MSG_ERROR, "ERROR: can't resolve %s\n", listen_name);
			return qfalse;
		}
		if(itf->h_addrtype != AF_INET)
		{
			MsgPrint(MSG_ERROR, "ERROR: %s is not an IPv4 address\n", listen_name);
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
						valid_options = Sv_AddAddressMapping(argv[ind]);
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
	inSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(inSock < 0)	{
		MsgPrint(MSG_ERROR, "ERROR: inSocket creation failed (%s)\n", strerror(errno));
		return qfalse;
	}
#ifdef USE_ALT_OUTPORT
	outSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(outSock < 0)	{
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
		MsgPrint(MSG_NORMAL, "Listening on address %s (%s)\n", listen_name, inet_ntoa(listen_addr));
		address.sin_addr.s_addr = listen_addr.s_addr;
	}
	else
		address.sin_addr.s_addr = htonl(INADDR_ANY);

	address.sin_port = htons(master_port);
	if(bind(inSock, (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s)\n", strerror(errno));
		SocketError_close(inSock);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Listening   UDP port %hu -=(  Kingpin  )=-\n", ntohs(address.sin_port));


	/* KPQ3 */
	address.sin_port = htons(master_port_kpq3);
	if (bind(inSock_kpq3, (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s)\n", strerror(errno));
		SocketError_close(inSock_kpq3);
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
		SocketError_close(outSock_kpq3);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Server out  UDP port %hu -=( KingpinQ3 )=-\n", ntohs(address.sin_port));
	//END UDP OUT KPQ3


	// UDP OUT
	// Deliberately use a different port for outgoing traffic in order
	// to confuse NAT UDP "connection" tracking and thus delist servers
	// hidden by NAT
	address.sin_port = htons(master_port + 1);

	if(bind(outSock, (struct sockaddr *)&address, sizeof(address)) != 0)	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s)\n", strerror(errno));
		SocketError_close(outSock);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Server out  UDP port %hu -=(  Kingpin  )=-\n", ntohs(address.sin_port));
	//END UDP OUT
#endif

////////////////////////////////////////////////////////
// listen on TCP for gamespy
////////////////////////////////////////////////////////
	inSock_tcp = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //hypov8
	if (inSock_tcp == INVALID_SOCKET)
	{
		printf("Server: Error at socket(): %i\n", ERRORNUM);
		SocketError_close(inSock_tcp);
		return qfalse;
	}

	//sockaddr_in service;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(master_port_gs); // master_port + 1000); //hypov8 todo: add startup cmd switch?

	if (bind(inSock_tcp, (struct sockaddr *)&address, sizeof(address)) != 0)
	{
		MsgPrint(MSG_ERROR, "ERROR: socket binding failed (%s)\n", strerror(errno));
		SocketError_close(inSock_tcp);
		return qfalse;
	}
	MsgPrint(MSG_NORMAL, "Listening   TCP port %hu -=(  gamespy  )=-\n", ntohs(address.sin_port));

	if (listen(inSock_tcp, 10) == SOCKET_ERROR) //hypo todo: test. is 10 enough?
	{
		printf("listen(): Error listening on socket %i.\n", ERRORNUM);
		SocketError_close(inSock_tcp);
		return qfalse;
	}
///////////////
//end tcp
///////////////

		MsgPrint(MSG_NORMAL, "-==========================================-\n");
		printf("listen() is OK, I'm waiting for connections...\n");


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

#define ADDRESS_LENGTH 16
#define ADDRESS_LENGTHIPADD 33 //16+16+1 //hypov8 ip+ip+=
static const char *ipIgnoreFile = "ip_ignore.txt";
static const char *ipConvertFile = "ip_rename.txt"; //hypov8 ip rename

typedef struct
{
	char            address[ADDRESS_LENGTH];	// Dotted quad
} ignoreAddress_t;

#define PARSE_INTERVAL		60	// seconds

static time_t   lastParseTime = 0;
static int      numIgnoreAddresses = 0;
static ignoreAddress_t *ignoreAddresses = NULL;
static ignoreAddress_t *ipAddresses = NULL; //hypov8 ip rename

/*
====================
parseIgnoreAddress
====================
*/
static qboolean parseIgnoreAddress(void) //hypov8 will allways load file when a new ip request
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

	f = fopen(ipIgnoreFile, "r");

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
ignoreAddress

Check whether or not to ignore a specific address
====================
*/
static qboolean ignoreAddress(const char *address)
{
	int             i;

	if(!parseIgnoreAddress())
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
	if(i < numIgnoreAddresses)
		return qtrue;

	return qfalse;
}



/*
====================
parseIPConversion
====================
*/
static void parseIPConversion(void) //hypov8 file loaded at start?
{
//	int             numAllocIPAddresses = 1;
	FILE           *f = NULL;
	int             i;
	qboolean			skipLine;

	//last_dns_time = crt_time;

#if 0
	numIPRename = 0;
	ipAddresses = malloc(sizeof(ignoreAddress_t) * numAllocIPAddresses);

	// Alloc failed, fail parsing
	if (ipAddresses == NULL)
		return qfalse;
#endif

	f = fopen(ipConvertFile, "r");

	if (!f)
	{
		free(ipAddresses);
		ipAddresses = NULL;
		return /*qfalse*/;
	}

	while (!feof(f))
	{
		char            c;
		char            buffer[ADDRESS_LENGTHIPADD]; // [ADDRESS_LENGTH];

		i = 0;

		// Skip whitespace
		do
		{
			c = (char)fgetc(f);
		} while (c != EOF && isspace(c));

		if (c != EOF)
		{
			memset(buffer, 0, sizeof(buffer)); //hypov8 reset buffer length to zero
			skipLine = qfalse; //add hypo allow comments
			do
			{
				if (i >= ADDRESS_LENGTHIPADD)
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
				Sv_AddAddressMapping(buffer); //hypov8 add ip
#if 0
			strcpy(ipAddresses[numIPRename].address, buffer);

			numIPRename++;

			// Make list bigger
			if (numIPRename >= numAllocIPAddresses)
			{
				ignoreAddress_t *new;

				numAllocIPAddresses *= 2;
				new = realloc(ipAddresses, sizeof(ignoreAddress_t) * numAllocIPAddresses);

				// Alloc failed, fail parsing
				if (new == NULL)
				{
					fclose(f);
					free(ipAddresses);
					ipAddresses = NULL;
					return qfalse;
				}

				ipAddresses = new;
			}
#endif
		}
	}

	fclose(f);

	return /*qtrue*/;
}



/*
====================
replaceNullChar

replace null with \
====================
*/
void replaceNullChar(char packet[1024], int packet_len)
{
	int i;
	char s;
//	char *out_packet;
	//int packet_len = strlen(packet);

	//new_packet = (char*)packet;

	for (i = 0; i <= packet_len; i++)
	{
		s = packet[i];
		if (s == '\0')
			s = '\\';

		if (i == packet_len)
			s = '\0';

		packet[i] = s;
	}
	//return out_packet;

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
	socklen_t       addrlen;
	int             nb_bytes;
	SOCKET_NET      sock;
	char            packet[MAX_PACKET_SIZE + 1];	// "+ 1" because we append a '\0'
	qboolean        valid_options;
	fd_set          rfds;
	struct timeval  tv;
	qboolean isTCP, isKPQ3;
	int iSendResult;
	SOCKET_NET fd_sok;

	signal(SIGINT, cleanUp);
	signal(SIGTERM, cleanUp);

	// Get the options from the command line
	valid_options = ParseCommandLine(argc, argv);

	//hypov8 alocate ip name conversion
	parseIPConversion();


	MsgPrint(MSG_NORMAL, "Kingpin master (version " VERSION " " __DATE__ " " __TIME__ ")\n");

	// If there was a mistake in the command line, print the help and exit
	if(!valid_options)
	{
		PrintHelp();
		return EXIT_FAILURE;
	}

	// Initializations
	if(!SysInit() || !UnsecureInit() || !SecInit() || !SecureInit())
		return EXIT_FAILURE;
	MsgPrint(MSG_NORMAL, "\n");

	// Until the end of times...
	while (!exitNow)
	{
		FD_ZERO(&rfds);
		FD_SET(inSock, &rfds);
		FD_SET(inSock_kpq3, &rfds);
		FD_SET(inSock_tcp, &rfds);
#ifdef USE_ALT_OUTPORT
		FD_SET(outSock, &rfds);
		FD_SET(outSock_kpq3, &rfds);
#endif
		tv.tv_sec = tv.tv_usec = 0;

		//pick highest socket. hypo note: dont know why it works, but it does :)
		fd_sok = inSock;
		if (inSock_kpq3 > fd_sok)
			fd_sok = inSock_kpq3;
		if (inSock_tcp > fd_sok)
			fd_sok = inSock_tcp;
#ifdef USE_ALT_OUTPORT
		if (outSock > fd_sok)
			fd_sok = outSock;
		if (outSock_kpq3 > fd_sok)
			fd_sok = outSock_kpq3;
#endif

		// Check for new data every 100ms
		if (select(fd_sok+1, &rfds, NULL, NULL, &tv) <= 0)
		{
			Sys_Sleep(100); //100 milliseconds
			continue;
		}

		isTCP = 0;
		isKPQ3 = 0;
		memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues

		if (FD_ISSET(inSock, &rfds))	{
			sock = inSock;
		}
		else if (FD_ISSET(inSock_kpq3, &rfds))	{
			isKPQ3 = 1;
			sock = inSock_kpq3;
		}
		else if (FD_ISSET(inSock_tcp, &rfds))	{
			isTCP = 1;
			sock = inSock_tcp;
		}
#ifdef USE_ALT_OUTPORT
		else if (FD_ISSET(outSock, &rfds))	{
			sock = outSock;
		}
		else if (FD_ISSET(outSock_kpq3, &rfds))	{
			isKPQ3 = 1;
			sock = outSock_kpq3;
		}
#endif
		else
			continue;
	
	
		addrlen = sizeof(address);
		crt_time = time(NULL);

		// hypo try resolve dns names every 5 min(dynamic ip's)
		if (!isStaticIPHost && last_dns_time < crt_time)	{
			last_dns_time = crt_time + (5*60*1000); //5 min
			Sv_ResolveAddressMappings();
		}

// Get the next valid message
		if (isTCP)
		{
			char *echo = "\\basic\\\\secure\\TXKOAT"; //21

			tmpClientOut_tcp = accept(sock, (struct sockaddr *)&address, (socklen_t*)&addrlen);
			if (tmpClientOut_tcp == INVALID_SOCKET)		{
				printf("accept failed with error: %i\n", ERRORNUM);
				SocketError_close(tmpClientOut_tcp);
				continue;
			}

			// Ignore abusers
			if (ignoreAddress(inet_ntoa(address.sin_addr)))		{
				printf("Ignore abusers: \n");
				SocketError_close(tmpClientOut_tcp);
				continue;
			}

			if (FloodIpStoreReject(&address))	{
				char tmp[21];
				sprintf(tmp, "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
				printf("%-21s ---> FLOOD: Client Rejected\n", tmp );
				SocketError_close(tmpClientOut_tcp);
				continue;
			}

			//send empty packet then echo
			iSendResult = send(tmpClientOut_tcp, 0, 0, 0);
			iSendResult = send(tmpClientOut_tcp, echo, strlen(echo), 0);
			if (iSendResult == SOCKET_ERROR) 	{
				printf("send failed with error: %i\n", ERRORNUM);
				SocketError_close(tmpClientOut_tcp);
				continue; // return 1;
			}

			nb_bytes = recv(tmpClientOut_tcp, packet, MAX_PACKET_SIZE, 0);
			if (nb_bytes == SOCKET_ERROR)	{
				printf("receive failed with error: %i\n", ERRORNUM);
				SocketError_close(tmpClientOut_tcp);
				continue;
			}

			iSendResult = send(tmpClientOut_tcp, 0, 0, 0);

			/* check if we have recieved usable data */
			if (IsGameSpyPacket(packet)) //if //gamename//gspylite// and NOT //list//
				nb_bytes = recv(tmpClientOut_tcp, packet, MAX_PACKET_SIZE, 0);

		}
		else //end TCP
			nb_bytes = recvfrom(sock, packet, sizeof(packet) - 1, 0, (struct sockaddr *)&address, &addrlen);	//use UDP

		if(nb_bytes <= 0) //hypov8 note, error from sending ping after a shutdown. remove??
		{
			server_t       *server;
			char tmp[21];

			sprintf(tmp, "%s:%hu", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
			MsgPrint(MSG_DEBUG, "%-21s ---> @%lld returned %d bytes ( shutdown )\n", tmp, crt_time, nb_bytes);

			server = Sv_GetByAddr(&address, qfalse);
			if (server == NULL)
				continue;
			server->timeout = crt_time /*+ (5*1000)*/; //remove server??

			continue;
		}

		// Ignore abusers
		if (ignoreAddress(inet_ntoa(address.sin_addr)))
			continue;

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
		if(nb_bytes < MIN_PACKET_SIZE)		{
			MsgPrint(MSG_WARNING, "WARNING: rejected packet from %s (size = %d bytes)\n", peer_address, nb_bytes);
			continue;
		}

		if(ntohs(address.sin_port) < 1024)		{
			MsgPrint(MSG_WARNING, "WARNING: rejected packet from %s (source port = 0)\n", peer_address);
			continue;
		}

		// Append a '\0' to make the parsing easier
		packet[nb_bytes] = '\0';

		//Handle Message(tcp);
		if (isTCP) //TCP GameSpy listen
		{
			/* hypov8 packet sent in strange format, replace '\0' with '\\' */
			if (packet[0] == '\0' && nb_bytes)
				replaceNullChar(packet, nb_bytes);

			/* process message */
			HandleGspyMessage(packet, &address);

			/* shutdown the connection since we're done */
			if (shutdown(tmpClientOut_tcp, TCP_SHUTBOTH) == SOCKET_ERROR)
				printf("shutdown client TCP failed with error: %i\n", ERRORNUM);
			
			 /* close client temporary socket */
			SocketError_close(tmpClientOut_tcp);

		}
		else if (isKPQ3) //kingpinq3
		{
			HandleMessageKPQ3(packet + 4, &address); //remove YYYY
		}
		else //kingpin
		{
			HandleMessage(packet, &address);
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

	va_start(args, format);
	result = vprintf(format, args);
	va_end(args);

	fflush(stdout);

	return result;
}
