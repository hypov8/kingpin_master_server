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


// ---------- Private variables ---------- //

//ignore
static int              ignoreAddresses_count = 10;
static ignoreAddress_t* ignoreAddresses = NULL;

static const char *ipIgnoreFile_Name   = "ip_ignore.txt";
static const char *ipConvertFile_Name  = "ip_rename.txt"; //hypov8 ip rename
static const char *ipOfflineFile_Name  = "ip_offline.txt"; //hypov8 ip rename

static int serverListsToPing_count = 16; //init
// ---------- Public variables ---------- //

ipPortList_t *serverListsToPing = NULL;


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



qboolean CFG_AddServerToList(int numServers, char *ip, char *port)
{
	// Make list bigger. if needed
	if (numServers >= serverListsToPing_count)
	{
		ipPortList_t *tmp_ptr;

		serverListsToPing_count *= 2;
		tmp_ptr = serverListsToPing;
		serverListsToPing = realloc(serverListsToPing, sizeof(ipPortList_t) * serverListsToPing_count);

		// Alloc failed, fail parsing
		if (serverListsToPing == NULL) {
			serverListsToPing = tmp_ptr;
			return qfalse;
		}
	}

	//add server
	strcpy(serverListsToPing[numServers].address, ip);
	strcpy(serverListsToPing[numServers].port, port);

	return qtrue;
}


/*
====================
CFG_Offline_Parse

hypo offline list to ping
====================
*/
static int CFG_Offline_Parse()
{
	FILE *f = NULL;
	char *portPtr, c, s[ADDRESS_LENGTHMAX], p[PORT_LENGTH];
	int   j, numOfflineList = 0;

	MsgPrint(MSG_DEBUG, "Loading... %s\n", ipOfflineFile_Name);
	f = fopen(ipOfflineFile_Name, "r");
	if (!f)
		return -1;

	//loop through each line
	while (fgets(s, ADDRESS_LENGTHMAX, f) != NULL)// && !feof(f))
	{
		c = s[0];

		// Skip comment lines
		if (isspace(c) || c == '/' ||c == '\\' )
			continue;

		//check for port
		portPtr = strstr(s, ":");
		if (portPtr == NULL)	
			continue;	//hypov8 todo error message??

		*portPtr++ = '\0'; //ternimate ip string
		memset(p, 0, PORT_LENGTH);
		for (j = 0; j < PORT_LENGTH-1; j++) 
		{
			c = portPtr[0];
			if (!c || isspace(c) || c == '/') 
				break;
			p[j] = c;
			portPtr++;
		}

		//copy port and ip to list
		if (!CFG_AddServerToList(numOfflineList, s, p))
			break;

		numOfflineList += 1;

		if (feof(f))
			break;
	}

	fclose(f);

	return numOfflineList;
}



// ---------- Public functions ---------- //


void CFG_PingServerList(int numwebList, qboolean isWebGSPort)
{
	int i;
	char *message;

	if (numwebList)
	{
		if (isWebGSPort)
		{
			message = M2S_GETSTATUS_GS;
			MsgPrint(MSG_NORMAL, 
				"LIST-GS:  Sending \'\\\\status\\\\\' to %3d servers\n", numwebList);
		}
		else
		{
			message = M2S_GETSTATUS_YYYY;
			MsgPrint(MSG_NORMAL, 
				"LIST-GP:  Sending \'yyyystatus\' to %3d servers\n", numwebList);
		}

		for ( i = 0; i < numwebList; i++ )
		{
			Sv_PingOfflineList(serverListsToPing[i].address, serverListsToPing[i].port, 
				isWebGSPort, message);
		}
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
	//int numAllocOfflineList = 3;
	int numOfflineList = 0;

	MsgPrint(MSG_DEBUG, "Processing Offline List\n");

	if (!serverListsToPing)
		return;

	Sv_MemCheck("load offline begin");

	numOfflineList = CFG_Offline_Parse();
	if (numOfflineList >0)
	{
		CFG_PingServerList(numOfflineList, qfalse);
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

	/*if (offlineAddresses != NULL)
		free(offlineAddresses);*/

	if (serverListsToPing != NULL)
		free(serverListsToPing);

}
