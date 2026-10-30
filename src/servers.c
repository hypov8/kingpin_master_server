/*
	servers.c

	Server list and address mapping management for xrealmaster

	Copyright (C) 2004  Mathieu Olivier

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


#include "common.h"
#include "servers.h"


// ---------- Constants ---------- //

// Address hash bitmask
#define HASH_BITMASK (hash_table_size - 1)


// ---------- Variables ---------- //

// All server structures are allocated in one block in the "servers" array.
// Each used slot is also part of a linked list in "hash_table". A simple
// hash of the address and port of a server gives its index in the table.
static server_t *servers = NULL;
static size_t   max_nb_servers = DEFAULT_MAX_NB_SERVERS;
static size_t   nb_servers = 0;
static server_t **hash_table = NULL;
static size_t   hash_table_size = (1 << DEFAULT_HASH_SIZE);

// Last allocated entry in the "servers" array.
// Used as a start index for finding a free slot in "servers" more quickly
static unsigned int last_alloc;

// Variables for Sv_GetFirst, Sv_GetNext and Sv_RemoveCurrentAndGetNext
static server_t *crt_server = NULL;
static server_t **prev_pointer = NULL;
static int      crt_hash_ind = -1;

// List of address mappings. They are sorted by "from" field (IP, then port)
static addrmap_t *sv_addrmaps = NULL;


// ---------- Private functions ---------- //


/*
====================
Sv_AddressHash

Compute the hash of a server address
====================
*/
static unsigned int Sv_AddressHash(const struct sockaddr_in *address)
{
	qbyte          *addr = (qbyte *) & address->sin_addr.s_addr;
	qbyte          *port = (qbyte *) & address->sin_port;
	qbyte           hash;

	hash = addr[0] ^ addr[1] ^ addr[2] ^ addr[3] ^ port[0] ^ port[1];
	return hash & HASH_BITMASK;
}


/*
====================
Sv_RemoveAndGetNextPtr

Remove a server from the list and returns its "next" pointer
====================
*/
static server_t *Sv_RemoveAndGetNextPtr(server_t * sv, server_t ** prev)
{
	char tmpIP[128];
	char time[21];
	int timeout;

	timeout = (int)(crt_time - sv->timeout);

	nb_servers--;
	snprintf(tmpIP, sizeof(tmpIP), "%s:%hu",
		inet_ntoa(sv->address.sin_addr), ntohs(sv->address.sin_port));

	sprintf(time, "%d", timeout);

	MsgPrint(MSG_WARNING, "%-21s ---- Timeout sec:%05s      Stored (total: %u) \n",
		tmpIP, time, nb_servers); // hash

	// Mark this structure as "free"
	sv->active = qfalse;

	*prev = sv->next;
	return sv->next;
}


/*
====================
Sv_ResolveAddr

Resolve an internet address
name may include a port number, after a ':'
====================
*/
qboolean Sv_ResolveAddr(const char *name, struct sockaddr_in *addr)
{
	int len = strlen(name);
	char address[ADDRESS_LENGTHMAX], port[PORT_LENGTH], *ptr;
	struct hostent *host = NULL;
	u_long ulAddr = INADDR_NONE;

	//shoulde  never happen...
	if (len >= ADDRESS_LENGTHMAX)
	{
		MsgPrint(MSG_ERROR, "ERROR: Address to long %s\n", name);
		return qfalse;
	}

	port[0] = 0;
	strcpy(address, name);

	// Find the port in the address
	ptr = strchr(address, ':');
	if (ptr)
	{
		strncpy(port, ptr+1, PORT_LENGTH-1);
		port[PORT_LENGTH-1] = 0;
		ptr[0] = 0;
	}
	if (!address[0])
	{
		MsgPrint(MSG_ERROR, "ERROR: Can\'t resolve %s\n", name);
		return qfalse;
	}

	ulAddr = inet_addr(address);	//ipv4 string
	if (ulAddr != INADDR_NONE && ulAddr != INADDR_ANY)
	{
		;//ulAddr = ntohl(ulAddr);
	}
	else
	{	// failed. must be dns

		//getaddrinfo(namecpy,port, ) //todo:
		host = gethostbyname(address); //memory leak..
		if(host == NULL)
		{
			MsgPrint(MSG_ERROR, "ERROR: Can\'t resolve %s\n", address);
			return qfalse;
		}
		if(host->h_addrtype != AF_INET)
		{
			MsgPrint(MSG_ERROR, "ERROR: %s is not an IPv4 address\n", address);
			return qfalse;
		}
		//convert
		ulAddr = *(u_long*)host->h_addr; //h_addr_list[0]
	}

	// 0.0.0.0 addresses are forbidden
	if (ulAddr == INADDR_ANY)
	{
		MsgPrint(MSG_ERROR, "ERROR: Mapping from or to 0.0.0.0 is forbidden\n");
		return qfalse;
	}

	// Do NOT allow mapping to loopback addresses
	if (((ulAddr >> 0)&0xff) == 127) //127.0.0.0-127.255.255.255
	{	
		MsgPrint(MSG_ERROR, "ERROR: Mapping to a loopback address is forbidden\n");
		return qfalse;
	}

	// Build the structure
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	//memcpy(&addr->sin_addr.s_addr, (void*)&ulAddr, sizeof(ulAddr));
	addr->sin_addr.s_addr = ulAddr;

	//port. 
	if (port[0])
		//note: not used anymore. resolved earlier
		addr->sin_port = htons((u_short)atoi(port)); //add port

	MsgPrint(MSG_DEBUG_EXT, "%-21s DNS resolved to %s\n",
			address, inet_ntoa(addr->sin_addr));

	return qtrue;
}


/*
====================
Sv_InsertAddrmapIntoList

Insert an addrmap structure to the addrmaps list
====================
*/
static void Sv_InsertAddrmapIntoList(addrmap_t * new_map)
{
	addrmap_t      *addrmap = sv_addrmaps;
	addrmap_t     **prev = &sv_addrmaps;

	// Stop at the end of the list, or if the addresses become too high
	while(addrmap != NULL && addrmap->from.sin_addr.s_addr <= new_map->from.sin_addr.s_addr)
	{
		// If we found the right place
		if(addrmap->from.sin_addr.s_addr == new_map->from.sin_addr.s_addr &&
			addrmap->from.sin_port >= new_map->from.sin_port)
		{
			// If a mapping is already recorded for this address
			if(addrmap->from.sin_port == new_map->from.sin_port)
			{
				MsgPrint(MSG_WARNING,
						 "WARNING: Address %s:%hu has several mappings\n",
						 inet_ntoa(new_map->from.sin_addr), ntohs(new_map->from.sin_port));
				if ( !addrmap->used )
				{
					*prev = addrmap->next;
					free(addrmap);
				}
			}
			break;
		}

		prev = &addrmap->next;
		addrmap = addrmap->next;
	}

	// Insert it
	new_map->next = *prev;
	*prev = new_map;

	MsgPrint(MSG_DEBUG, "%-21s Mapped to \"%s\" (%s:%hu)\n",
			 new_map->from_string, new_map->to_string,
			 inet_ntoa(new_map->to.sin_addr), ntohs(new_map->to.sin_port));
}


/*
====================
Sv_GetAddrmap

Look for an address mapping corresponding to addr
====================
*/
static const addrmap_t *Sv_GetAddrmap(const struct sockaddr_in *addr)
{
	const addrmap_t *addrmap = sv_addrmaps;
	const addrmap_t *found = NULL;

	// Stop at the end of the list, or if the addresses become too high
	while(addrmap != NULL && addrmap->from.sin_addr.s_addr <= addr->sin_addr.s_addr)
	{
		// If it's the right address
		if(addrmap->from.sin_addr.s_addr == addr->sin_addr.s_addr)
		{
			// If the exact mapping isn't there
			if(addrmap->from.sin_port > addr->sin_port)
				return found;

			// If we found the exact address
			if(addrmap->from.sin_port == addr->sin_port)
				return addrmap;

			// General mapping
			// Store it in case we don't find the exact address mapping
			if(addrmap->from.sin_port == 0)
				found = addrmap;
		}

		addrmap = addrmap->next;
	}

	return found;
}


/*
====================
Sv_ResolveAddrmap

Resolve an addrmap structure and check the parameters validity
====================
*/
static qboolean Sv_ResolveAddrmap(addrmap_t * addrmap)
{
	// Resolve the addresses
	if (!Sv_ResolveAddr(addrmap->from_string, &addrmap->from) ||
		!Sv_ResolveAddr(addrmap->to_string, &addrmap->to))
	{ 
		//add hypov8 display ip rename issues
		MsgPrint(MSG_ERROR, "ERROR: Mapping from %s to %s not resolved\n",
			addrmap->from_string, addrmap->to_string);
		return qfalse;
	}

	return qtrue;
}


/*
====================
Sv_IsActive

Return qtrue if a server is active.
Test if the server has timed out and remove it if it's the case.
====================
*/
static qboolean Sv_IsActive(server_t * server)
{

	// If the entry isn't even used
	if(!server->active)
		return qfalse;

	// If the server has timed out
	if(server->timeout < crt_time)
	{
		unsigned int    hash;
		server_t      **prev, *sv;

		hash = Sv_AddressHash(&server->address);
		prev = &hash_table[hash];
		sv = hash_table[hash];

		while(sv != server)
		{
			prev = &sv->next;
			sv = sv->next;
		}

		Sv_RemoveAndGetNextPtr(sv, prev);
		return qfalse;
	}

	return qtrue;
}


// ---------- Public functions (servers) ---------- //

void Sv_MemCheck(char *printString)
{
#ifndef _DEBUG
	(void) printString;
#else
	int i = -1, j = 0;
	static SIZE_T lastMemSize = 0;
	static int hashUsed =0;

	GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

	if ( pmc.PeakWorkingSetSize > lastMemSize ){
		if (lastMemSize !=0 )
			MsgPrint(MSG_ERROR, "mem size changed (%s)\n", printString);
		lastMemSize = pmc.PeakWorkingSetSize;
	}
#endif
}


/*
====================
Sv_SetHashSize

Set a new hash size value
====================
*/
qboolean Sv_SetHashSize(unsigned int size)
{
	// Too late?
	if(hash_table != NULL)
		return qfalse;

	// Too big?
	if(size > MAX_HASH_SIZE)
		return qfalse;

	hash_table_size = 1 << size;
	return qtrue;
}


/*
====================
Sv_SetMaxNbServers

Set a new hash size value
====================
*/
qboolean Sv_SetMaxNbServers(unsigned int nb)
{
	// Too late?
	if(servers != NULL)
		return qfalse;

	max_nb_servers = nb;
	return qtrue;
}


/*
====================
Sv_Init

Initialize the server list and hash table
====================
*/
qboolean Sv_Init(void)
{
	size_t          array_size;

	// Allocate "servers" and clean it
	array_size = max_nb_servers * sizeof(server_t);
	servers = malloc(array_size);
	if(!servers)
	{
		MsgPrint(MSG_ERROR, "ERROR: can\'t allocate the servers array (%s)\n", strerror(errno));
		return qfalse;
	}
	last_alloc = max_nb_servers - 1;
	memset(servers, 0, array_size);
	MsgPrint(MSG_NORMAL, "%u server records allocated\n", max_nb_servers);

	// Allocate "hash_table" and clean it
	array_size = hash_table_size * sizeof(hash_table[0]);
	hash_table = malloc(array_size);
	if(!hash_table)
	{
		MsgPrint(MSG_ERROR, "ERROR: can\'t allocate the hash table (%s)\n", strerror(errno));
		free(servers);
		return qfalse;
	}
	memset(hash_table, 0, array_size);
	MsgPrint(MSG_NORMAL, "Hash table allocated (%u entries)\n", hash_table_size);

	return qtrue;
}


/*
====================
Sv_PingTimeOut

Search for a particular server in the list; add it if necessary
====================
*/
void Sv_PingTimeOut_GamePort(void)
{
	server_t		*sv;
	unsigned long	sv_addr;
	//char			*char_sv_addr;
	unsigned short  sv_port;
	SOCKET_NET snd_sock_kp = (outSock_udp != INVALID_SOCKET) ? outSock_udp : inSock_udp;
	SOCKET_NET snd_sock_kpq3 = (outSock_kpq3 != INVALID_SOCKET) ? outSock_kpq3 : inSock_kpq3;

	// ping every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// No more next server
		if (sv == NULL)
			return;
		// server is safe. more than 60 sec to timeout
		if (sv->timeout > (crt_time + 60))
			continue;
		//server waiting for previous responce
		if (sv->isWaitResponce)
			continue;

		//char_sv_addr = inet_ntoa(sv->address.sin_addr);
		sv_port = ntohs(sv->address.sin_port);
		sv_addr = ntohl(sv->address.sin_addr.s_addr);

		if ( sv->protocol == 32 || sv->protocol == 34 )
		{
			sendto( snd_sock_kp /*#ifdef USE_ALT_OUTPORT	 outSock_udp #else inSock_udp #endif*/
			, M2S_PING_YYYY, strlen(M2S_PING_YYYY), 0,
				(const struct sockaddr *)&sv->address, sizeof(sv->address));
		}
		else if ( ( sv->protocol == 74 || sv->protocol == 75 ) )
		{
			sendto( snd_sock_kpq3 /*#ifdef USE_ALT_OUTPORT outSock_kpq3 #else inSock_kpq3 #endif*/
			, M2S_GETINFO_KPQ3, strlen(M2S_GETINFO_KPQ3), 0,
				( const struct sockaddr *)&sv->address, sizeof(sv->address));
		}
		else
			continue;

		// Extra debugging info
		MsgPrint(MSG_DEBUG,
			"About to timeout, ping serve: IP:\"%u.%u.%u.%u:%hu\", proto:%u\n",
			(int)(sv_addr >> 24), ((sv_addr >> 16) & 0xFF),
			((sv_addr >> 8) & 0xFF), (sv_addr & 0xFF), sv_port, sv->protocol);
	}
}


/*
====================
Sv_PingOfflineList

Ping servers from a text file. non public servers
====================
*/
void Sv_PingOfflineList(ipPortList_t *pServer, const char *packet, const char *packetGS)
{
	struct sockaddr_in  tmpServerAddress;
	server_t           *sv;
	char                tmpIP[ADDRESS_LENGTHMAX + PORT_LENGTH + 4];
	int                 nb_bytes_gs = 0;
	int                 nb_bytes_gp = 0;
	qboolean            validGSpy = 0, gs;
	time_t              timeDiff;
	SOCKET_NET          snd_sock = (outSock_udp != INVALID_SOCKET)? outSock_udp : inSock_udp;
	u_short             svPort;


	Sv_MemCheck("Sv_PingOfflineList1");
	 
	if (!pServer || !pServer->sin_port_game || !pServer->sin_port_gspy) 
	{
		if (!pServer)
			snprintf(tmpIP, sizeof(tmpIP), "%s:%s", "", "");
		else
			snprintf(tmpIP, sizeof(tmpIP), "%s:%s", pServer->address, pServer->port);
		MsgPrint(MSG_WARNING, "%-21s ---> ERROR: Offline server failed\n", tmpIP);
		return;
	}

	//get ip (can be dns), not using port
	if (!Sv_ResolveAddr(pServer->address, &tmpServerAddress)) {
		snprintf(tmpIP, sizeof(tmpIP), "%s:%s", pServer->address, pServer->port);
		MsgPrint(MSG_WARNING, "%-21s ---> ERROR: Offline ResolveAddr failed\n", tmpIP);
		return;
	}

	// if server is in list. dont ping it again
	for (sv = Sv_GetFirst(); sv != NULL; sv = Sv_GetNext())
	{
		// 1. Compare the IP address
		if (sv->address.sin_addr.s_addr == tmpServerAddress.sin_addr.s_addr) 
		{
			// Get the tracked game port out of the active server entry
			svPort = ntohs(sv->address.sin_port);
			gs = (sv->gsPort && sv->gsPort == pServer->sin_port_gspy);

			// 2. Cross-check BOTH ports against the active engine state entry
			if (svPort == pServer->sin_port_game || gs )
			{
				// Entry is stale and needs an update pass. Stop searching.
				timeDiff = crt_time + TIMEOUT_HEARTBEAT1;
				if (sv->timeout < timeDiff)
				{						
					validGSpy = gs && sv->gsPort_valid;//dont send to game port
					break; 
				}

				// Entry is totally fresh. Log it and skip sending redundant packets.
				snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(sv->address.sin_addr), pServer->sin_port_game);
				MsgPrint(MSG_DEBUG_EXT, "%-21s ---- Existing server up-to-date. Skip ping.\n", tmpIP);
				return;
			}
		}
	}


	// ping offline servers not in master, or outdated
	// --- DUAL PING STRATEGY ---
	
	// Probe 1: Send the status packet to the Status/GameSpy Port
	tmpServerAddress.sin_port = htons(pServer->sin_port_gspy);
	nb_bytes_gs = sendto(snd_sock, packetGS, strlen(packetGS), 0, 
		(const struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress));

	// Probe 2: Send a fallback status packet directly to the raw Connect/Game Port
	if (!validGSpy)
	{
		tmpServerAddress.sin_port = htons(pServer->sin_port_game);
		nb_bytes_gp = sendto(snd_sock, packet, strlen(packet), 0, 
			(const struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress));
	}

	// Error logging based on the primary status port probe result
	if (nb_bytes_gs == SOCKET_ERROR && (!validGSpy && nb_bytes_gp == SOCKET_ERROR)) {
		snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", pServer->address, pServer->sin_port_game);
		MsgPrint(MSG_WARNING, "%-21s ---> WARNING: \'sendto\' offlineList failed. Error: %i\n", tmpIP, ERRORNUM);
	}

	Sv_MemCheck("Sv_PingOfflineList2");
}

/*
====================
Sv_GetByAddr

Search for a particular server in the list; add it if necessary
====================
*/
server_t       *Sv_GetByAddr(const struct sockaddr_in *address, qboolean add_it)
{
	server_t      **prev, *sv;
	unsigned int    hash;
	const addrmap_t *addrmap = Sv_GetAddrmap(address); //addressReMap
	unsigned int    startpt;
	char			tmpIP[128];

	// Allow servers on a loopback address ONLY if a mapping is defined for them
	if((ntohl(address->sin_addr.s_addr) >> 24) == 127 && addrmap == NULL)
	{
		MsgPrint(MSG_WARNING, "%-21s ---> WARNING: server isn\'t allowed (loopback address)\n",peer_address);
		return NULL;
	}

	hash = Sv_AddressHash(address);
	prev = &hash_table[hash];
	sv = hash_table[hash];

	while(sv != NULL)
	{
		// We check the timeout values while browsing this list
		if(sv->timeout < crt_time)		{
			sv = Sv_RemoveAndGetNextPtr(sv, prev);
			continue;
		}

		// Found!
		if(sv->address.sin_addr.s_addr == address->sin_addr.s_addr &&
			sv->address.sin_port == address->sin_port)
		{
			// Put it on top of the list (it's useful because heartbeats
			// are almost always followed by infoResponses)
			snprintf(tmpIP, sizeof(tmpIP), "%s:%hu",
				inet_ntoa(sv->address.sin_addr), ntohs(sv->address.sin_port));
			MsgPrint(MSG_DEBUG, "%-21s ---- Existing server \n", tmpIP);

			*prev = sv->next;
			sv->next = hash_table[hash];
			hash_table[hash] = sv;

			return sv;
		}

		prev = &sv->next;
		sv = sv->next;
	}

	if(!add_it)
		return NULL;

	// Look for the first free entry in "servers"
	startpt = last_alloc;
	for(;;)
	{
		last_alloc = (last_alloc + 1) % max_nb_servers;

		// Free entry found?
		if(!Sv_IsActive(&servers[last_alloc]))
			break;

		// No more room
		if(last_alloc == startpt)
			return NULL;
	}
	sv = &servers[last_alloc];

	// Initialize the structure
	memset(sv, 0, sizeof(*sv));
	memcpy(&sv->address, address, sizeof(sv->address));
	sv->addressReMap = addrmap;

	//mark remap as used. dont delete later if an error
	if ( addrmap != NULL )
	{
		addrmap_t *addrmapTmp;
		addrmapTmp = (addrmap_t*)addrmap;
		addrmapTmp->used = qtrue;
	}
	// Add it to the list it belongs to
	sv->next = hash_table[hash];
	hash_table[hash] = sv;
	nb_servers++;

	MsgPrint(MSG_NORMAL, "%-21s ---+ %-22s Stored (total: %u)\n",
		peer_address, "New server", nb_servers);
	MsgPrint(MSG_DEBUG, 
		"  - index: %u\n"
		"  - hash: 0x%02X\n",
		last_alloc, hash);

	return sv;
}


/*
====================
Sv_GetFirst

Get the first server in the list
====================
*/
server_t       *Sv_GetFirst(void)
{
	crt_server = NULL;
	prev_pointer = NULL;
	crt_hash_ind = -1;

	return Sv_GetNext();
}


/*
====================
Sv_GetNext

Get the next server in the list
====================
*/
server_t       *Sv_GetNext(void)
{
	for(;;)
	{
		// If there is a current server, follow the link
		if(crt_server != NULL)
		{
			prev_pointer = &crt_server->next;
			crt_server = crt_server->next;
		}

		// If we don't have the next server yet
		if(crt_server == NULL)
		{
			// Search the hash table for the next server
			while(crt_hash_ind < (int)(hash_table_size - 1))
			{
				crt_hash_ind++;

				if(hash_table[crt_hash_ind] != NULL)
				{
					crt_server = hash_table[crt_hash_ind];
					prev_pointer = &hash_table[crt_hash_ind];
					break;
				}
			}
		}

		// Did we hit the end of the list?
		if(crt_server == NULL)
			return NULL;

		// If the new current server has timed out, remove it
		if (crt_server->timeout < crt_time)
			crt_server = Sv_RemoveAndGetNextPtr(crt_server, prev_pointer);
		else
			return crt_server;
	}
}



// ---------- Public functions (address mappings) ---------- //

/*
====================
Sv_Add_unResolvedAddressMapping

Add an unresolved address mapping to the list
mapping must be of the form "addr1:port1=addr2:port2", ":portX" are optional
====================
*/
qboolean Sv_Add_unResolvedAddressMapping(const char *mapping)
{
	char           *map_string, *to_ip;
	addrmap_t      *addrmap, *tmp;

	// Get a working copy of the mapping string
	map_string = x_strdup(mapping);
	if(map_string == NULL)
	{
		MsgPrint(MSG_ERROR, "ERROR: can\'t allocate address mapping string\n");
		return qfalse;
	}

	// Find the '='
	to_ip = strchr(map_string, '=');
	if(to_ip == NULL)
	{
		MsgPrint(MSG_ERROR, "ERROR: invalid syntax in address mapping string\n");
		free(map_string);
		return qfalse;
	}
	*to_ip++ = '\0';

	//check for existing <from> and update <to>
	tmp = sv_addrmaps;
	while ( tmp != NULL )
	{
		//found existing server ip, update remap address. 
		// note: server remap pointer is not updated at runtime
		if ( !strcmp(tmp->from_string, map_string) )
		{
			//clear old ref and set new remap
			free(tmp->to_string); //free old string
			tmp->to_string = x_strdup(to_ip);
			if(tmp->to_string == NULL)
			{
				MsgPrint(MSG_ERROR, "ERROR: can\'t allocate address mapping string.\n");
				free(map_string);
				return qfalse;
			}
			free(map_string);
			//memset(&tmp->from, 0, sizeof(tmp->from)); //hypov8 note: keep old ip
			//memset(&tmp->to, 0, sizeof(tmp->to));
			return qtrue;
		}
		tmp = tmp->next;
	}

	// Allocate the structure
	addrmap = malloc(sizeof(*addrmap));
	if(addrmap == NULL)
	{
		MsgPrint(MSG_ERROR, "ERROR: can\'t allocate address mapping structure\n");
		free(map_string);
		return qfalse;
	}
	memset(addrmap, 0, sizeof(*addrmap));
	addrmap->from_string = x_strdup(map_string);
	addrmap->to_string = x_strdup(to_ip);
	if(addrmap->from_string == NULL || addrmap->to_string == NULL)
	{
		MsgPrint(MSG_ERROR, "ERROR: can\'t allocate address mapping strings\n");
		if (addrmap->to_string== NULL)
			free(addrmap->to_string);
		if (addrmap->from_string == NULL)
			free(addrmap->from_string);
		free(addrmap);
		free(map_string);
		return qfalse;
	}

	// Add it on top of "addrmaps"
	addrmap->next = sv_addrmaps;
	sv_addrmaps = addrmap;

	free(map_string);

	return qtrue;
}


/*
====================
Sv_ResolveAddressMappings

Resolve the address mapping list 'ip_rename.txt'
====================
*/
qboolean Sv_ResolveAddressMappings(void)
{
	//hypov8 alocate ip name conversion. Load .txt
	if (CFG_IPConvert_Check() )
	{
		addrmap_t      *unresolved = sv_addrmaps;
		addrmap_t      *addrmap;
		qboolean        succeeded = qtrue;

		sv_addrmaps = NULL;

		while (unresolved != NULL)
		{
			// Remove it from the unresolved list
			addrmap = unresolved;
			unresolved = unresolved->next;

			// Continue the resolution, even if there's an error
			if (!Sv_ResolveAddrmap(addrmap) && addrmap->used == qfalse)
			{
				free(addrmap->from_string);
				free(addrmap->to_string);
				free(addrmap);
				succeeded = qfalse;
			}
			else
				Sv_InsertAddrmapIntoList(addrmap); //insert even if failed(keep old entry)
		}

		return succeeded;
	}

	return qfalse;
}


void SV_ClearMem(void)
{
#ifdef _DEBUG
	addrmap_t      *addrmap = sv_addrmaps;

	if (servers!= NULL)
		free(servers);
	if (hash_table!= NULL)
		free(hash_table);

	while ( addrmap!= NULL )
	{
		addrmap_t *tmp;
		free(addrmap->from_string);
		free(addrmap->to_string);
		tmp = addrmap;
		addrmap = addrmap->next;
		free(tmp);
	}
#endif
}

