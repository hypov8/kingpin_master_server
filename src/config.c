/*
handel config files

ip_ignore.txt
ip_offline.txt
ip_rename.txt

*/

#include "common.h"
#include "messages.h"
#include "servers.h"

// ---------- Constants ---------- //
#define PARSE_INTERVAL     60 // seconds


// ---------- Types ---------- //

typedef struct
{
	char  address[ADDRESS_LENGTH];	// Dotted quad
} ignoreAddress_t;

typedef struct
{
	int           count;
	SOCKET_NET    sock;
	ipPortList_t *list; // Stores only the DNS/domain items
} asyncDNSList_t;


// ---------- Private variables ---------- //

//ignore
static int              ignoreAddresses_count = 10;
static ignoreAddress_t* ignoreAddresses = NULL;

static const char *ipIgnoreFile_Name           = "ip_ignore.txt";
static const char *ipConvertFile_Name          = "ip_rename.txt"; //ip rename
static const char *ipOfflineFileName_gamePort  = "ip_offline.txt";
static const char *ipOfflineFileName_gameSpy   = "ip_offline_gs.txt";

//last request type. use gamespy or Game protocol

static ipPortList_t *serverListsToPing = NULL;
static int           serverListsToPing_count = 64; //init


// ---------- Public variables ---------- //



// ---------- Private functions ---------- //


/*
====================
CFG_Ignore_parseAddress

will always load file when a new ip request
====================
*/
static qboolean CFG_Ignore_parseAddress(void)
{
	int           i, c;
	FILE         *f = NULL;
	qboolean      skipLine;
	static int    num_ignore = 0;
	static time_t lastUpdateTime = 0;
	char buffer[ADDRESS_LENGTH];
	
	if (ignoreAddresses == NULL)
		return 0;

	// Only parse periodically
	if (lastUpdateTime > crt_time)
	{
		return num_ignore;
	}

	lastUpdateTime = crt_time + PARSE_INTERVAL;
	num_ignore = 0;

	
	MsgPrint(MSG_DEBUG, "Loading... %s\n", ipIgnoreFile_Name);
	f = fopen(ipIgnoreFile_Name, "r");
	if(!f)
	{
		num_ignore = 0;
		return 0;
	}

	while(!feof(f))
	{
		i = 0;

		// Skip whitespace
		do {
			c = fgetc(f);
		}
		while(c != EOF && isspace(c));

		if (c != EOF)
		{
			memset(buffer, 0, sizeof(buffer));
			skipLine = qfalse; //add hypo allow comments
			do
			{
				if (i >= ADDRESS_LENGTH)
				{
					buffer[i - 1] = '\0';
					break;
				}

				buffer[i] = (char)c;

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
			} while ((c = fgetc(f)) != EOF);

			if (!skipLine)
			{
				strcpy(ignoreAddresses[num_ignore].address, buffer);
				num_ignore++;

				// Make list bigger
				if (num_ignore >= ignoreAddresses_count)
				{
					//ignoreAddress_t *tmp_ptr;

					ignoreAddresses_count *= 2;
					//tmp_ptr = ignoreAddresses;
					ignoreAddresses = realloc(ignoreAddresses, sizeof(ignoreAddress_t) * ignoreAddresses_count);

					// Alloc failed, fail parsing
					if ( ignoreAddresses == NULL )
					{
						fclose(f);
						ignoreAddresses = NULL;
						return num_ignore;
					}
				}
			}
		}
	}

	fclose(f);

	return num_ignore;
}

qboolean CFG_GrowServerList(int numServers)
{
	// Make list bigger. if needed
	if (numServers >= serverListsToPing_count)
	{
		ipPortList_t *tmp_ptr;

		if (serverListsToPing_count == 0)
			serverListsToPing_count = 32;
		else
			serverListsToPing_count *= 2;

		tmp_ptr = serverListsToPing;
		serverListsToPing = realloc(serverListsToPing, sizeof(ipPortList_t) * serverListsToPing_count);

		// Alloc failed, fail parsing
		if (serverListsToPing == NULL) {
			serverListsToPing = tmp_ptr;
			return qfalse;
		}
	}
	return qtrue;
}

qboolean CFG_AddServerToList(int svIndex, char *ip, char *port, qboolean isGSPort)
{
	u_short parsedPort;

	if (!CFG_GrowServerList(svIndex))
		return qfalse;

	//add server
	strcpy(serverListsToPing[svIndex].address, ip); //ADDRESS_LENGTHMAX
	strcpy(serverListsToPing[svIndex].port, port);  //PORT_LENGTH

	parsedPort = (u_short)atoi(port);

	// Map the dual-port relationships immediately on ingestion ---
	if (isGSPort)
	{
		// The web list provided the GameSpy Status port
		serverListsToPing[svIndex].sin_port_gspy = parsedPort;
		serverListsToPing[svIndex].sin_port_game = parsedPort + 10u; // Game port is 10 higher
	}
	else
	{
		// The web list provided the raw Connect/Game port
		serverListsToPing[svIndex].sin_port_game = parsedPort;
		serverListsToPing[svIndex].sin_port_gspy = parsedPort - 10u; // Status port is 10 lower
	}

	return qtrue;
}


/*
====================
CFG_Offline_Parse

hypo offline list to ping
====================
*/
static int CFG_Offline_Parse(qboolean isGSPort)
{
	FILE *f = NULL;
	char  buff[ADDRESS_LENGTHMAX];
	char  bufferIP[ADDRESS_LENGTHMAX], bufferPort[PORT_LENGTH];
	int   numOfflineList = 0;
	const char *filename;

	if (isGSPort)
		filename = ipOfflineFileName_gameSpy;
	else
		filename = ipOfflineFileName_gamePort;

	MsgPrint(MSG_DEBUG, "Loading... %s\n", filename);
	f = fopen(filename, "r");
	if (!f)
	{
		MsgPrint(MSG_WARNING, "Cant open %s\n", filename);
		return -1;
	}

	//loop through each line
	while (fgets(buff, ADDRESS_LENGTHMAX, f) != NULL)// && !feof(f))
	{
		//get adderess, handle invalid chars
		if (!Com_GetIpPortFromLine(buff, bufferIP, bufferPort)) {
			continue;
		}

		//copy port and ip to list
		if (bufferIP[0] != '\0')
		{
			if (!CFG_AddServerToList(numOfflineList, bufferIP, bufferPort, isGSPort))
				break; //failed to expand list

			numOfflineList += 1;
		}

		if (feof(f))
			break;
	}

	fclose(f);

	return numOfflineList;
}



// The thread worker function (Cross-Platform)
#ifdef _WIN32
static DWORD WINAPI ThreadedDNSResolverPump(LPVOID lpParam)
#else
static void *ThreadedDNSResolverPump(void *lpParam)
#endif
{
	asyncDNSList_t *cargo = (asyncDNSList_t *)lpParam;
	struct sockaddr_in addr;
	int i;

	for (i = 0; i < cargo->count; i++)
	{
		ipPortList_t *srv = &cargo->list[i];

		// This handles the blocking gethostbyname calls safely in the background
		if (!Sv_ResolveAddr(srv->address, &addr))
			continue;

		// Probe 1: GameSpy Port
		addr.sin_port = htons(srv->sin_port_gspy);
		sendto(cargo->sock, M2S_GETSTATUS_GS, strlen(M2S_GETSTATUS_GS), 0, (struct sockaddr *)&addr, sizeof(addr));

		// Probe 2: Game Port
		addr.sin_port = htons(srv->sin_port_game);
		sendto(cargo->sock, M2S_GETSTATUS_YYYY, strlen(M2S_GETSTATUS_YYYY), 0, (struct sockaddr *)&addr, sizeof(addr));
	}

	free(cargo->list);
	free(cargo);
	return 0;
}


static void CFG_SendToThread_offline(SOCKET_NET snd_sock, int dnsCount, asyncDNSList_t *cargo)
{
	cargo->count = dnsCount;
	cargo->sock  = snd_sock;

#ifdef _WIN32
	HANDLE hThread = CreateThread(NULL, 0, ThreadedDNSResolverPump, cargo, 0, NULL);
	if (hThread != NULL) 
	{
		CloseHandle(hThread); // Detach instantly on Windows
	} 
	else 
	{
		free(cargo->list); 
		free(cargo);
	}
#else
	pthread_t threadId;
	if (pthread_create(&threadId, NULL, ThreadedDNSResolverPump, cargo) == 0) 
	{
		pthread_detach(threadId); // Detach instantly on Linux
	} 
	else 
	{
		free(cargo->list); 
		free(cargo);
	}
#endif
}



// ---------- Public functions ---------- //


void CFG_PingServerList(int numwebList, qboolean isGSPort, ipListType_t listType)
{
	int i;
	char *prefix, *portType, *query, tmpIP[ADDRESS_LENGTHMAX + PORT_LENGTH + 4];
	int dnsCount = 0;
	SOCKET_NET snd_sock = (outSock_udp != INVALID_SOCKET) ? outSock_udp : inSock_udp;
	asyncDNSList_t *cargo = NULL;

	if (!numwebList || serverListsToPing == NULL)
		return;

	switch (listType)
	{
		default:
		case LIST_WEB:     prefix = "HTTP "; break;
		case LIST_OFFLINE: prefix = "LOCAL"; break;
	}
	query = isGSPort? "\'\\\\status\\\\\'": "\'yyyystatus\'";
	portType = isGSPort? "GSpy" : "Game";

	MsgPrint(MSG_NORMAL, "LOADING IP-LIST: Src: %s  Port: %s  Count: %-3d  Query: %s \n", 
		prefix, portType, numwebList, query);


	for ( i = 0; i < numwebList; i++ )
	{
		ipPortList_t *pServer = &serverListsToPing[i];
		u_long ulAddr = inet_addr(pServer->address);

		//let ipv4 process
		if (ulAddr != INADDR_NONE && ulAddr != INADDR_ANY)
		{
			Sv_PingOfflineList(pServer, M2S_GETSTATUS_YYYY, M2S_GETSTATUS_GS);
		}
		else
		{
			//offload dns lookups. can pause main thread.
			//valid?
			if (!pServer || !pServer->sin_port_game || !pServer->sin_port_gspy)
			{
				if (!pServer)
					snprintf(tmpIP, sizeof(tmpIP), "%s:%s", "", "");
				else
					snprintf(tmpIP, sizeof(tmpIP), "%s:%s", pServer->address, pServer->port);
				MsgPrint(MSG_WARNING, "%-21s ---> ERROR: Offline server failed\n", tmpIP);
				continue;
			}

			//failed alloc
			if (dnsCount < 0)
				continue; 

			if (dnsCount == 0 && cargo == NULL)
			{
				cargo = malloc(sizeof(asyncDNSList_t));
				if (!cargo)
				{
					dnsCount = -1;
					continue;
				}

				cargo->list = malloc(sizeof(ipPortList_t) * (numwebList - i)); //todo sort offline with dns last
				if (!cargo->list) 
				{
					free(cargo);
					dnsCount = -1;
					continue;
				}
			}

			if (cargo != NULL)
			{
				memcpy(&cargo->list[dnsCount], pServer, sizeof(ipPortList_t));
				dnsCount++;
			}
		}
	}


	// 3. Deployed the deferred domains to the background thread pool
	if (dnsCount > 0 && cargo != NULL)
	{
		CFG_SendToThread_offline(snd_sock, dnsCount, cargo);
	}
	else if (cargo != NULL)
	{	//just incase..
		if (cargo->list) 
			free(cargo->list);
		free(cargo);
	}
}



/*
====================
CONFIG_IgnoreCheck

Check whether or not to ignore a specific address
====================
*/
qboolean CFG_Ignore_Check(const char *address)
{
	int i, numIgnore;

	numIgnore = CFG_Ignore_parseAddress();
	if(!numIgnore)
	{	// Couldn't parse, allow the address
		return qfalse;
	}

	for(i = 0; i < numIgnore; i++)
	{
		if(strcmp(address, ignoreAddresses[i].address) == 0)
			break;
	}

	// It matched
	if (i < numIgnore){
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
void CFG_Offline_Begin()
{
	static qboolean isGSPort = qfalse; //this will get gamespy lists first
	int numOfflineList = 0;

	MsgPrint(MSG_DEBUG, "Processing Offline List\n");

	if (!serverListsToPing)
		return;

	isGSPort = !isGSPort; //switch between GS and Gameport

	Sv_MemCheck("load offline begin");

	numOfflineList = CFG_Offline_Parse(isGSPort);
	if (numOfflineList >0)
	{
		CFG_PingServerList(numOfflineList, isGSPort, LIST_OFFLINE);
	}
	else if (numOfflineList == -1)
	{	// Couldn't parse, offline list
		MsgPrint(MSG_DEBUG, "OFFLINELIST: Failed\n");
	}

	Sv_MemCheck("load offline end");
}



/*
====================
MAST_parseIPConversionFile

file loaded at start
====================
*/
qboolean CFG_IPConvert_Check(void)
{
	FILE     *f = NULL;
	int       i;
	qboolean  skipLine;
	char      c;
	char      buffer[ADDRESS_LENGTHMAX];

	MsgPrint(MSG_DEBUG, "Loading... %s\n", ipConvertFile_Name);
	f = fopen(ipConvertFile_Name, "r");
	if (!f)
	{
		MsgPrint(MSG_WARNING, "WARNING: Could not open \'%s\' \n", ipConvertFile_Name);
		return qfalse;
	}
	//todo put to buffer and close
	while (!feof(f))
	{
		i = 0;

		// Skip whitespace
		do
		{
			c = (char)fgetc(f);
		} while (c != EOF && isspace(c));

		if (c != EOF)
		{
			memset(buffer, 0, sizeof(buffer));
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

//allocate mem for ip lists
qboolean CFG_Init()
{
	//create memory for servers
	serverListsToPing = malloc(sizeof(ipPortList_t) * serverListsToPing_count);
	if (serverListsToPing == NULL)
	{	// Alloc failed
		MsgPrint(MSG_ERROR, "ERROR: CFG malloc Failed1. (Error: %d)\n", ERRORNUM);
		return qfalse;
	}

	ignoreAddresses = malloc(sizeof(ignoreAddress_t) * ignoreAddresses_count);
	if (ignoreAddresses == NULL)
	{	// Alloc failed
		MsgPrint(MSG_ERROR, "ERROR: CFG malloc Failed2. (Error: %d)\n", ERRORNUM);
		return qfalse;
	}

	return qtrue;
}

void CFG_ClearMem()
{
	if (ignoreAddresses != NULL)
		free(ignoreAddresses);

	if (serverListsToPing != NULL)
		free(serverListsToPing);
}
