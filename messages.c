/*
	messages.c

	Message management for xrealmaster

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
#include "messages.h"
#include "servers.h"

//gamespy encryption
//#include "gs_encrypt/sb_crypt.h"


//#include "gs_encrypt/gsmsalg.h"
//#include "gs_encrypt/master.h"
//#include "gs_encrypt/dk_essentials.h" // FS



// ---------- Constants ---------- //

// Timeouts (in secondes)
#define TIMEOUT_HEARTBEAT		320 //kingpin default 300
#define TIMEOUT_INFORESPONSE	(15 * 60)

// Period of validity for a challenge string (in secondes)
#define TIMEOUT_CHALLENGE 3

//hypov8 allow a bit of time for ping responce
#define TIMEOUT_PING 10

// Maximum size of a reponse packet
#define MAX_PACKET_SIZE 1400


// Types of messages (with samples):


//#define S2M_HEARTBEAT "heartbeat Kingpin-1" //hypo kp1
#define S2M_HEARTBEAT		"\\heartbeat\\" //hypo kp1
#define S2M_HEARTBEAT_YYYY	"ÿÿÿÿheartbeat\n" //hypo kp1
#define S2M_GAMENAME		"gamename\\kingpin" //hypo kp1
#define S2M_SHUTDOWN_YYYY	"ÿÿÿÿshutdown"		//kingpin1 master shutdown, server change, map etc
#define S2M_ACK_YYYY		"ÿÿÿÿack"			//recieved ack 
#define S2M_PING_YYYY		"ÿÿÿÿping"			//recieved ping (initilized server...)
#define S2M_PRINT_YYYY		"ÿÿÿÿprint\n"			//recieved print (after sending status...)
#define S2M_ERROR_STR		"Info string length exceeded\n"

// "getinfo A_Challenge"
#define M2S_GETINFO "\\status\\" //hypov8 kpq3 "getinfo"
#define M2S_GETINFO_YYYY "ÿÿÿÿstatus\n" //hypov8 kpq3 "getinfo"
#define M2S_PING_YYYY "ÿÿÿÿping\n"	// send ping, hoping to recieve ack
#define M2S_ACK_YYYY  "ÿÿÿÿack\n"	//server sent ping, reponce with an ack


// "infoResponse\n\\pure\\1\\..."
#define S2M_INFORESPONSE "infoResponse\x0A"

// "getservers 68 empty full"
#define C2M_GETSERVERS "getservers Kingpin-1" //hypo kp1

//gamespy browser requests
#define B2M_INITCONTACT			"\\gamename\\gspylite\\" 
#define B2M_GETSERVERS			"\\list\\" 
//#define B2M_GETSERVERS_GSLIST	"\\&\\\x1\x3\\\\\\\\kingpin\\gslive\\"
#define B2M_GETSERVERS_GSLIST2 "\\gamename\\gamespy2\\"

//87.175.221.101:61916 --->invalid GameSpy(\gamename\gamespy2\gamever\20603020\enctype\0\validate\Up
//kV3Mfn\final\\list\cmp\gamename\kps)

 // "\x00&\x00\x01\x03\x00\x00\x00\x00kingpin\x00gslive\""


#define M2B_ECHOREPLY	"\\basic\\\\secure\\TXKOAT" //echo reply to gamespy


// "getserversResponse\\...(6 bytes)...\\...(6 bytes)...\\EOT\0\0\0"
#define M2C_GETSERVERSREPONSE "getserversResponse"

#define C2M_GETMOTD "getmotd"
#define M2C_MOTD    "motd "





///kpq3 stuff

// "heartbeat Kingpinq3\n"
#define S2M_HEARTBEAT_KPQ3	"heartbeat KingpinQ3-1"
#define S2M_HEARTBEAT_DP	"heartbeat DarkPlaces" // more accepted protocol name at other masters

// "getinfo A_Challenge"
#define M2S_GETINFO_KPQ3	"getinfo"

// "infoResponse\n\\pure\\1\\..."
#define S2M_INFORESPONSE_KPQ3	"infoResponse\x0A"

// "getservers 68 empty full"
#define C2M_GETSERVERS_KPQ3		"getservers KingpinQ3-1"
#define C2M_GETSERVERS2_KPQ3	"getservers " // if not using darkplaces protocol

// "getserversResponse\\...(6 bytes)...\\...(6 bytes)...\\EOT\0\0\0"
#define M2C_GETSERVERSREPONSE_KPQ3 "getserversResponse"

#define C2M_GETMOTD_KPQ3 "getmotd"
#define M2C_MOTD_KPQ3    "motd "



// ---------- Private functions ---------- //

/*
====================
SearchInfostring

Search an infostring for the value of a key
====================
*/
static char    *SearchInfostring(const char *infostring, const char *key)
{
	static char     value[256];
	char            crt_key[256];
	size_t          value_ind, key_ind;
	char            c;

	if(*infostring++ != '\\')
		return NULL;

	value_ind = 0;
	for(;;)
	{
		key_ind = 0;

		// Get the key name
		for(;;)
		{
			c = *infostring++;

			if(c == '\0')
				return NULL;
			if(c == '\\' || key_ind == sizeof(crt_key) - 1)
			{
				crt_key[key_ind] = '\0';
				break;
			}

			crt_key[key_ind++] = c;
		}

		// If it's the key we are looking for, save it in "value"
		if(!strcmp(crt_key, key))
		{
			for(;;)
			{
				c = *infostring++;

				if(c == '\0' || c == '\\' || value_ind == sizeof(value) - 1)
				{
					value[value_ind] = '\0';
					return value;
				}

				value[value_ind++] = c;
			}
		}

		// Else, skip the value
		for(;;)
		{
			c = *infostring++;

			if(c == '\0')
				return NULL;
			if(c == '\\')
				break;
		}
	}
}


/*
====================
BuildChallenge

Build a challenge string for a "getinfo" message
====================
*/
static const char *BuildChallenge(void)
{
	static char     challenge[CHALLENGE_MAX_LENGTH];
	size_t          ind;
	size_t          length = CHALLENGE_MIN_LENGTH - 1;	// We start at the minimum size

	// ... then we add a random number of characters
	length += rand() % (CHALLENGE_MAX_LENGTH - CHALLENGE_MIN_LENGTH + 1);

	for(ind = 0; ind < length; ind++)
	{
		char            c;

		do
		{
			c = 33 + rand() % (126 - 33 + 1);	// -> c = 33..126
		} while(c == '\\' || c == ';' || c == '"' || c == '%' || c == '/');

		challenge[ind] = c;
	}

	challenge[length] = '\0';
	return challenge;
}


/*
====================
SendGetInfo

Send a "getinfo" message to a server
====================
*/
static void SendGetStatus(server_t * server)
{
	int netfail;
	char            msg[64] =  M2S_GETINFO;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
		fprintf(stderr, "%s <--- 'status'\n", peer_address);

	netfail = WSAGetLastError();
	if (netfail)
		MsgPrint(MSG_DEBUG, "%s <--- 'status'--== WSAGetLastError ==-- \"%i\"\n", peer_address, netfail);
}

/*
====================
SendGetInfo

Send a "status" message to a server
====================
*/
static void SendGetInfo(server_t * server)
{
	int netfail;
	char            msg[64] = M2S_GETINFO_YYYY;

	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		strncpy(server->challenge, BuildChallenge(), sizeof(server->challenge) - 1);
		server->challenge_timeout = crt_time + TIMEOUT_CHALLENGE;
	}
	//server->address.sin_port = 31620;
#if 0 //hypo test local ip
	server->address.sin_addr.S_un.S_un_b.s_b1 = 110;
	server->address.sin_addr.S_un.S_un_b.s_b2 = 175;
	server->address.sin_addr.S_un.S_un_b.s_b3 = 51;
	server->address.sin_addr.S_un.S_un_b.s_b4 = 202;
#endif
	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
		MsgPrint(MSG_DEBUG, "%s <--- 'YYYYstatus'\n", peer_address);

	netfail = WSAGetLastError();
	if (netfail)
		MsgPrint(MSG_DEBUG, "%s <--- 'YYYYstatus'--== WSAGetLastError ==-- \"%i\"\n", peer_address, netfail);
}


/*
====================
SendGetInfo

Send a "getinfo" message to a server
====================
*/
static void SendGetInfoKPQ3(server_t * server)
{
	char            msg[64] = "\xFF\xFF\xFF\xFF" M2S_GETINFO_KPQ3 " ";

	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		strncpy(server->challenge, BuildChallenge(), sizeof(server->challenge) - 1);
		server->challenge_timeout = crt_time + TIMEOUT_CHALLENGE;
	}

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
	if (sendto(outSock_kpq3, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
	{
		//fprintf(stderr, "packet seems to have sent %i.\n", server->address.sin_port);
		MsgPrint(MSG_DEBUG, "%s <--- getinfo with challenge \"%s\"\n", peer_address, server->challenge);
	}
}

//kingpin
static void SendPing(server_t * server)
{
	int  netfail;
	char msg[64] = M2S_PING_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
		MsgPrint(MSG_DEBUG, "%s <--- 'Ping' sent\n", peer_address);

	netfail = WSAGetLastError();
	if (netfail)
		MsgPrint(MSG_DEBUG, "%s <--- 'Ping'--== WSAGetLastError ==-- \"%i\"\n", peer_address, netfail);
}

//kingpin
static void SendAck(server_t * server)
{
	int  netfail;
	char msg[64] = M2S_ACK_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
		MsgPrint(MSG_DEBUG, "%s <--- 'Ping' sent\n", peer_address);

	netfail = WSAGetLastError();
	if (netfail)
		MsgPrint(MSG_DEBUG, "%s <--- 'Ping'--== WSAGetLastError ==-- \"%i\"\n", peer_address, netfail);


}

/*
====================
HandleGetServers

Parse getservers requests and send the appropriate response
====================
*/
static void HandleGetServers(const char *msg, const struct sockaddr_in *addr, int isTCP, const char* challenge)
{
	const char     *packetheader = "";
	const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind;
	server_t       *sv;
	unsigned int    protocol;
	unsigned long    sv_addr;
	char			*char_sv_addr;
	char			tmp_packet[30];
	unsigned short  sv_port;
	qboolean        no_empty;
	qboolean        no_full;
	unsigned int    numServers = 0;
	char * challengeTmp;

	//new
	//unsigned char  *dest;
	//char *gamename = "QFWxY2";

	//int buflen = 0;
	unsigned char buff[6];
	////////

	// Check if there's a name before the protocol number
	// In this case, the message comes from a DarkPlaces-compatible client
	protocol = atoi(msg);

	challengeTmp = "GameSpy";
	if (challenge)
		challengeTmp = (char*)challenge;
	

	if (max_msg_level >= MSG_DEBUG) //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%s ---> getservers ( %s )\n", peer_address, challengeTmp); //%d, protocol

	no_empty = 0;
	no_full = 0;

	// Initialize the packet contents with the header
	packetind = headersize;
	memcpy(packet, packetheader, headersize);
	memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues


	// Add every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof(packet) - (7 + 6))
		{
			// End Of Transmission
			strcat(packet, "\\final\\");


			// Send the packet to the client
			if (isTCP)
				sendto(tmpClientOut_tcp, packet, strlen(packet), 0, (const struct sockaddr *)addr, sizeof(*addr));
			else
				sendto(inSock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));

				
			if (max_msg_level <= MSG_NORMAL) //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%s ---> getservers ( %s ) Servers: %u\n", peer_address, challengeTmp, numServers); //%d, protocol
			MsgPrint(MSG_DEBUG, "%s <--- getserversResponse (%u servers)\n", peer_address, numServers);

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		char_sv_addr = inet_ntoa(sv->address.sin_addr);
		sv_port = ntohs(sv->address.sin_port);
		sv_addr = ntohl(sv->address.sin_addr.s_addr);
		// Use the address mapping associated with the server, if any
		if (sv->addrmap != NULL)
		{
			const addrmap_t *addrmap = sv->addrmap;
			char_sv_addr = inet_ntoa(addrmap->to.sin_addr);

			sv_addr = ntohl(addrmap->to.sin_addr.s_addr);
			if (addrmap->to.sin_port != 0)
				sv_port = ntohs(addrmap->to.sin_port);
		}

		// Extra debugging info
		if (max_msg_level >= MSG_DEBUG)
		{
			MsgPrint(MSG_DEBUG,
				"Comparing server: IP:\"%u.%u.%u.%u:%hu\", p:%u, c:%hu\n",
				sv_addr >> 24, (sv_addr >> 16) & 0xFF,
				(sv_addr >> 8) & 0xFF, sv_addr & 0xFF, sv_port, sv->protocol, sv->nbclients);
		}

#if 1 //hypov8 allow all servers in gamespy. kp1 + kpq3
		// Check protocol, options
		if (challenge)
		{
			_strlwr((char*)challenge);
			if (!strncmp(challenge, "kingpin", strlen(challenge)))
			{
				if (sv->protocol != 32)
					continue;
			}
			else if (!strncmp(challenge, "quake2", strlen(challenge)))
			{
				//if (sv->protocol == 32 || sv->protocol == 74 || sv->protocol == 75)
				if (sv->protocol != 34)
					continue;
			}
			else if (!strncmp(challenge, "kingpinq3", strlen(challenge)))
			{
				if (!(sv->protocol == 74 || sv->protocol == 75))
					continue;
			}
		}

		//if (sv->protocol != 32 )
			//continue;	// Skip it
#endif

		if (isTCP == 2)
		{
			// Use the address mapping associated with the server, if any
			if (sv->addrmap != NULL)
			{
				buff[0] = sv->addrmap->to.sin_addr.S_un.S_un_b.s_b1;
				buff[1] = sv->addrmap->to.sin_addr.S_un.S_un_b.s_b2;
				buff[2] = sv->addrmap->to.sin_addr.S_un.S_un_b.s_b3;
				buff[3] = sv->addrmap->to.sin_addr.S_un.S_un_b.s_b4;

				if (sv->addrmap->to.sin_port != 0)
					memcpy(buff + 4, &sv->addrmap->to.sin_port, 2);
				else
					memcpy(buff + 4, &sv->address.sin_port, 2);
				packetind += 6;
			}
			else
			{
				buff[0] = sv->address.sin_addr.S_un.S_un_b.s_b1;
				buff[1] = sv->address.sin_addr.S_un.S_un_b.s_b2;
				buff[2] = sv->address.sin_addr.S_un.S_un_b.s_b3;
				buff[3] = sv->address.sin_addr.S_un.S_un_b.s_b4;

				memcpy(buff + 4, &sv->address.sin_port, 2);
				packetind += 6;
			}
			sprintf(packet, "%s%c%c%c%c%c%c", packet, buff[0], buff[1], buff[2], buff[3], buff[4], buff[5]);
		}
		else
		{
			sprintf(tmp_packet, "\\ip\\%s:%i", char_sv_addr, sv_port - 10); //-10 send query port to clients

			strcat(packet, tmp_packet);
			packetind += sizeof(tmp_packet);

			MsgPrint(MSG_DEBUG, "  - Sending server %u.%u.%u.%u:%hu\n",
				(qbyte)packet[packetind], (qbyte)packet[packetind + 1],
				(qbyte)packet[packetind + 2], (qbyte)packet[packetind + 3], sv_port);
		}
		numServers++;
	}
}


/*
====================
HandleGetServers

Parse getservers requests and send the appropriate response
====================
*/
static void HandleGetServersKPQ3(const char *msg, const struct sockaddr_in *addr)
{
	const char     *packetheader = "\xFF\xFF\xFF\xFF" M2C_GETSERVERSREPONSE "\\";
	const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind;
	server_t       *sv;
	unsigned int    protocol;
	unsigned int    sv_addr;
	unsigned short  sv_port;
	qboolean        no_empty;
	qboolean        no_full;
	unsigned int    numServers = 0;

	// Check if there's a name before the protocol number
	// In this case, the message comes from a DarkPlaces-compatible client
	protocol = atoi(msg);

	if (max_msg_level >= MSG_DEBUG) //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%s ---> getservers ( KPQ3 protocol %d )\n", peer_address, protocol);

	no_empty = (strstr(msg, "empty") == NULL);
	no_full = (strstr(msg, "full") == NULL);

	// Initialize the packet contents with the header
	packetind = headersize;
	memcpy(packet, packetheader, headersize);

	// Add every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof(packet) - (7 + 6))
		{
			// End Of Transmission
			packet[packetind] = 'E';
			packet[packetind + 1] = 'O';
			packet[packetind + 2] = 'T';
			packet[packetind + 3] = '\0';
			packet[packetind + 4] = '\0';
			packet[packetind + 5] = '\0';
			packetind += 6;

			// Send the packet to the client
			sendto(inSock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));

			if (max_msg_level <= MSG_NORMAL) //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%s ---> getservers ( KPQ3 protocol %d ) Servers: %i\n", peer_address, protocol, numServers);

			MsgPrint(MSG_DEBUG, "%s <--- getserversResponse (%u servers)\n", peer_address, numServers);

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		sv_addr = ntohl(sv->address.sin_addr.s_addr);
		sv_port = ntohs(sv->address.sin_port);

		// Extra debugging info
		if (max_msg_level >= MSG_DEBUG)
		{
			MsgPrint(MSG_DEBUG,
				"Comparing server: IP:\"%u.%u.%u.%u:%hu\", p:%u, c:%hu\n",
				sv_addr >> 24, (sv_addr >> 16) & 0xFF,
				(sv_addr >> 8) & 0xFF, sv_addr & 0xFF, sv_port, sv->protocol, sv->nbclients);

			if (sv->protocol != protocol)
				MsgPrint(MSG_DEBUG, "Reject: protocol %u != requested %u\n", sv->protocol, protocol);
			if (sv->nbclients == 0 && no_empty)
				MsgPrint(MSG_DEBUG, "Reject: nbclients is %hu/%hu && no_empty\n", sv->nbclients, sv->maxclients);
			if (sv->nbclients == sv->maxclients && no_full)
				MsgPrint(MSG_DEBUG, "Reject: nbclients is %hu/%hu && no_full\n", sv->nbclients, sv->maxclients);
		}

		// Check protocol, options
		if (sv->protocol != protocol || (sv->nbclients == 0 && no_empty) || (sv->nbclients == sv->maxclients && no_full))
		{

			// Skip it
			continue;
		}

		// Use the address mapping associated with the server, if any
		if (sv->addrmap != NULL)
		{
			const addrmap_t *addrmap = sv->addrmap;

			sv_addr = ntohl(addrmap->to.sin_addr.s_addr);
			if (addrmap->to.sin_port != 0)
				sv_port = ntohs(addrmap->to.sin_port);

			MsgPrint(MSG_DEBUG,
				"Server address mapped to %u.%u.%u.%u:%hu\n",
				sv_addr >> 24, (sv_addr >> 16) & 0xFF, (sv_addr >> 8) & 0xFF, sv_addr & 0xFF, sv_port);
		}

		// IP address
		packet[packetind] = sv_addr >> 24;
		packet[packetind + 1] = (sv_addr >> 16) & 0xFF;
		packet[packetind + 2] = (sv_addr >> 8) & 0xFF;
		packet[packetind + 3] = sv_addr & 0xFF;

		// Port
		packet[packetind + 4] = sv_port >> 8;
		packet[packetind + 5] = sv_port & 0xFF;

		// Trailing '\'
		packet[packetind + 6] = '\\';

		MsgPrint(MSG_DEBUG, "  - Sending server %u.%u.%u.%u:%hu\n",
			(qbyte)packet[packetind], (qbyte)packet[packetind + 1],
			(qbyte)packet[packetind + 2], (qbyte)packet[packetind + 3], sv_port);

		packetind += 7;
		numServers++;
	}
}


/*
====================
HandleInfoResponse

Parse infoResponse messages
====================
*/
static void HandleInfoResponse(server_t * server, const char *msg)
{
	char           *value;
	unsigned int    new_protocol = 0;
	unsigned short	new_maxclients = 0;

	MsgPrint(MSG_DEBUG, "%s ---> infoResponse\n", peer_address);

	// Check the challenge
	if(!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		MsgPrint(MSG_WARNING, "WARNING: infoResponse with obsolete challenge from %s\n", peer_address);
		return;
	}
	value = SearchInfostring(msg, "challenge");
	if(!value || strcmp(value, server->challenge))
	{
		MsgPrint(MSG_ERROR, "ERROR: invalid challenge from %s (%s)\n", peer_address, value);
		return;
	}

	// Check and save the values of "protocol" and "maxclients"
	value = SearchInfostring(msg, "protocol");
	if(value)
		new_protocol = atoi(value);
	value = SearchInfostring(msg, "maxclients");
	if(value)
		new_maxclients = (unsigned short)atoi(value);
	if(!new_protocol || !new_maxclients)
	{
		MsgPrint(MSG_ERROR,
				 "ERROR: invalid infoResponse from %s (protocol: %d, maxclients: %d)\n",
				 peer_address, new_protocol, new_maxclients);
		return;
	}
	server->protocol = new_protocol;
	server->maxclients = new_maxclients;

	// Save some other useful values
	value = SearchInfostring(msg, "clients");
	if(value)
		server->nbclients = (unsigned short)atoi(value);

	// Set a new timeout
	//Sv_SetTimeout(address, TIMEOUT_PING);
	server->timeout = crt_time + TIMEOUT_INFORESPONSE;
}

/*
====================
HandleInfoResponse

Parse infoResponse messages
====================
*/
static void HandleInfoResponseKPQ3(server_t * server, const char *msg)
{
	char           *value;
	unsigned int    new_protocol = 0;
	unsigned short  new_maxclients = 0;

	MsgPrint(MSG_DEBUG, "%s ---> infoResponse\n", peer_address);

	// Check the challenge
	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		MsgPrint(MSG_WARNING, "WARNING: infoResponse with obsolete challenge from %s\n", peer_address);
		return;
	}
	value = SearchInfostring(msg, "challenge");
	if (!value || strcmp(value, server->challenge))
	{
		MsgPrint(MSG_ERROR, "ERROR: invalid challenge from %s (%s)\n", peer_address, value);
		return;
	}

	// Check and save the values of "protocol" and "maxclients"
	value = SearchInfostring(msg, "protocol");
	if (value)
		new_protocol = atoi(value);
	value = SearchInfostring(msg, "sv_maxclients");
	if (value)
		new_maxclients = (unsigned short)atoi(value);
	if (!new_protocol || !new_maxclients)
	{
		MsgPrint(MSG_ERROR,
			"ERROR: invalid infoResponse from %s (protocol: %d, maxclients: %d)\n",
			peer_address, new_protocol, new_maxclients);
		return;
	}
	server->protocol = new_protocol;
	server->maxclients = new_maxclients;

	// Save some other useful values
	value = SearchInfostring(msg, "clients");
	if (value)
		server->nbclients = (unsigned short)atoi(value);

	// Set a new timeout
	server->timeout = crt_time + TIMEOUT_INFORESPONSE;
}


#define CHALLENGE_KEY "challenge\\"
#define MOTD_KEY      "motd\\"

/*
====================
HandleGetMotd

Parse getservers requests and send the appropriate response
====================
*/
static void HandleGetMotd(const char *msg, const struct sockaddr_in *addr)
{
	const char     *packetheader = "\xFF\xFF\xFF\xFF" M2C_MOTD "\"";
	const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	char            challenge[MAX_PACKET_SIZE];
	const char     *motd = "";	//FIXME
	size_t          packetind;
	char           *value;
	char            version[1024], renderer[1024];

	MsgPrint(MSG_DEBUG, "%s ---> getmotd\n", peer_address);

	value = SearchInfostring(msg, "challenge");
	if(!value)
	{
		MsgPrint(MSG_ERROR, "ERROR: invalid challenge from %s (%s)\n", peer_address, value);
		return;
	}

	strncpy(challenge, value, sizeof(challenge) - 1);
	challenge[sizeof(challenge) - 1] = '\0';

	value = SearchInfostring(msg, "renderer");
	if(value)
	{
		strncpy(renderer, value, sizeof(renderer) - 1);
		renderer[sizeof(renderer) - 1] = '\0';
		MsgPrint(MSG_DEBUG, "%s is using renderer %s\n", peer_address, value);
	}

	value = SearchInfostring(msg, "version");
	if(value)
	{
		strncpy(version, value, sizeof(version) - 1);
		version[sizeof(version) - 1] = '\0';
		MsgPrint(MSG_DEBUG, "%s is using version %s\n", peer_address, value);
	}

	// Initialize the packet contents with the header
	packetind = headersize;
	memcpy(packet, packetheader, headersize);

	strncpy(&packet[packetind], CHALLENGE_KEY, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(CHALLENGE_KEY);

	strncpy(&packet[packetind], challenge, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(challenge);
	packet[packetind++] = '\\';

	strncpy(&packet[packetind], MOTD_KEY, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(MOTD_KEY);

	strncpy(&packet[packetind], motd, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(motd);

	if(packetind > MAX_PACKET_SIZE - 2)
		packetind = MAX_PACKET_SIZE - 2;

	packet[packetind++] = '\"';
	packet[packetind++] = '\0';

	MsgPrint(MSG_DEBUG, "%s <--- motd\n", peer_address);

	// Send the packet to the client
	sendto(inSock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
}

// ---------- Public functions ---------- //

/*
====================
HandleMessage
kingpin
Parse a packet to figure out what to do with it
====================
*/
void HandleMessage(const char *msg, const struct sockaddr_in *address)
{
	server_t       *server;
	int				newPort = 0;
	int i;

	// If it's an heartbeat
	if(!strncmp(S2M_HEARTBEAT, msg, strlen(S2M_HEARTBEAT)))
	{
		//char            gameId[64];
		char *value;
		struct sockaddr_in *addPort;
		/*
		hypov8 port is -10 to use the listen port.
		game port uses YYYY first.
		 "\\heartbeat\\31500\\gamename\\kingpin"
		 */

		// Extract the game id
		value = SearchInfostring(msg, "gamename");
		if (value == NULL)
			return;

		if (!(strcmp(value, "kingpin") == 0))
		{
			MsgPrint(MSG_NORMAL, "%s ---> heartbeat (%s)\nNot Kingpin\n", peer_address, value);
			return;
		}

		value = SearchInfostring(msg, "heartbeat");
		if (value == NULL)
			return;
		newPort = atoi(value)+ 10;

		//server->address.sin_port = htons((unsigned short)newPort);

		/* hypov8
		add port if specified in heartbeat*/
		addPort = (struct sockaddr_in*)address; //hypov8 compiler nag...
		if (newPort)
			addPort->sin_port = htons((unsigned short)newPort);

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(addPort, qtrue);
		if (server == NULL)
		return;

		server->active = qtrue;

		/* set timeout value. */
		//Sv_SetTimeout(address, TIMEOUT_HEARTBEAT);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		
		SendGetInfo(server);

	}

	//Heartbeat
	else if (!strncmp(S2M_HEARTBEAT_YYYY, msg, strlen(S2M_HEARTBEAT_YYYY)))
	{
		char *value;
		//char *new_msg;

		//new_msg = (char*)msg;

		/*minus YYYYheartbeat\n*/
		//strcpy(msg, &msg[14], sizeof(msg-14));
		strcpy((char*)msg, &msg[strlen(S2M_HEARTBEAT_YYYY)]);

		/* fix for info strings to long in kp1 */
		for (i = 0; i < 5; i++) //loop 5 times. should be pleanty
		{
			if (!strncmp(S2M_ERROR_STR, msg, strlen(S2M_ERROR_STR)))
			{
				strcpy((char*)msg, &msg[strlen(S2M_ERROR_STR)]); 
				continue;
			}
			break;
		}

		// Extract the game id
		value = SearchInfostring(msg, "protocol");
		if (value == NULL)		{
			MsgPrint(MSG_NORMAL, "No protocol in game string\n");
			return;
		}

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL)
			return;

		server->protocol = atoi(value);
		server->active = qtrue;

		/* set timeout value. */
		//Sv_SetTimeout(address, TIMEOUT_HEARTBEAT);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		
	}

	else if (!strncmp(S2M_PRINT_YYYY, msg, strlen(S2M_PRINT_YYYY)))
	{
		char *value;

		/*minus YYYYheartbeat\n*/
		//strcpy(msg, &msg[14]);
		strcpy((char*)msg, &msg[strlen(S2M_PRINT_YYYY)]);

		/* fix for info strings to long in kp1 */
		for (i = 0; i < 5; i++) //loop 5 times. should be pleanty
		{
			if (!strncmp(S2M_ERROR_STR, msg, strlen(S2M_ERROR_STR)))
			{
				strcpy((char*)msg, &msg[strlen(S2M_ERROR_STR)]);
				continue;
			}
			break;
		}
		// Extract the game id
		value = SearchInfostring(msg, "protocol");
		if (value == NULL)		{
			MsgPrint(MSG_NORMAL, "No protocol in game string\n");
			return;
		}

		if (!(strcmp(value, "32") == 0))		{
			MsgPrint(MSG_NORMAL, "Game is not protocol 32\n");
			return;
		}

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL)
			return;

		server->protocol = atoi(value);
		server->active = qtrue;

		/* set timeout value. */
		//Sv_SetTimeout(address, TIMEOUT_HEARTBEAT);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;

	}


	/* server sent shutdown, check if status changed or quit */
	else if (!strncmp(S2M_SHUTDOWN_YYYY, msg, strlen(S2M_SHUTDOWN_YYYY)))
	{
		/* check for a valid server */
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
		{
			//server = Sv_GetByAddr(address, qtrue);
			//if (server == NULL)
			//	return;

			//SendGetInfo(server); //hypov8 server didnt send initial heartbeat, but try add anyway
			return;
		}

		/* set timeout value. */
		//Sv_SetTimeout(address, TIMEOUT_PING);
		server->timeout = crt_time + TIMEOUT_PING;

		/* check if server is active or shutdown */
		SendPing(server);
	}

	/* server sent ack, check if status changed or quit */
	else if (!strncmp(S2M_ACK_YYYY, msg, strlen(S2M_ACK_YYYY)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
			return;

		/* update timeout */
		//Sv_SetTimeout(address, TIMEOUT_HEARTBEAT);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;

	}

	// server sent ping
	else if (!strncmp(S2M_PING_YYYY, msg, strlen(S2M_PING_YYYY)))
	{
		/* check for a valid server */
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL)
			return;

		/* set timeout value. */
		//Sv_SetTimeout(address, TIMEOUT_HEARTBEAT);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		
		SendAck(server);
	}

	// If it's an infoResponse message
	else if(!strncmp(S2M_INFORESPONSE, msg, strlen(S2M_INFORESPONSE)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if(server == NULL)
			return;

		HandleInfoResponse(server, msg + strlen(S2M_INFORESPONSE));
	}

	// If it's a getservers request
	else if(!strncmp(C2M_GETSERVERS, msg, strlen(C2M_GETSERVERS)))
	{
		HandleGetServers(msg + strlen(C2M_GETSERVERS), address, qfalse, 0);
	}

	// If it's a getmotd request
	else if(!strncmp(C2M_GETMOTD, msg, strlen(C2M_GETMOTD)))
	{
		HandleGetMotd(msg + strlen(C2M_GETMOTD), address);
	}

	else
	{
		MsgPrint(MSG_NORMAL, "%s ---> invalid (%s)\n", peer_address, msg);

	}


}


/*
====================
HandleMessage
kingpinq3
Parse a packet to figure out what to do with it
====================
*/
void HandleMessageKPQ3(const char *msg, const struct sockaddr_in *address)
{
	server_t       *server;

	// If it's an heartbeat
	if (!strncmp(S2M_HEARTBEAT_DP, msg, strlen(S2M_HEARTBEAT_DP)))
	{
		char            gameId[64];

		// Extract the game id
		sscanf(msg + strlen(S2M_HEARTBEAT_DP) + 1, "%63s", gameId);
		MsgPrint(MSG_DEBUG, "%s ---> heartbeat\n", peer_address/*, gameId*/);

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL)
			return;

		server->active = qtrue;

		// If we haven't yet received any infoResponse from this server,
		// we let it some more time to contact us. After that, only
		// infoResponse messages can update the timeout value.
		if (!server->maxclients)
			server->timeout = crt_time + TIMEOUT_HEARTBEAT;

		// Ask for some infos
		SendGetInfoKPQ3(server);
	}

	// If it's an heartbeat
	else if (!strncmp(S2M_HEARTBEAT_KPQ3, msg, strlen(S2M_HEARTBEAT_KPQ3)))
	{
		char            gameId[64];

		// Extract the game id
		sscanf(msg + strlen(S2M_HEARTBEAT_KPQ3) + 1, "%63s", gameId);
		MsgPrint(MSG_DEBUG, "%s ---> heartbeat\n", peer_address/*, gameId*/);

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL)
			return;

		server->active = qtrue;

		// If we haven't yet received any infoResponse from this server,
		// we let it some more time to contact us. After that, only
		// infoResponse messages can update the timeout value.
		if (!server->maxclients)
			server->timeout = crt_time + TIMEOUT_HEARTBEAT;

		// Ask for some infos
		SendGetInfoKPQ3(server);
	}

	// If it's an infoResponse message
	else if (!strncmp(S2M_INFORESPONSE_KPQ3, msg, strlen(S2M_INFORESPONSE_KPQ3)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
			return;

		HandleInfoResponseKPQ3(server, msg + strlen(S2M_INFORESPONSE_KPQ3));
	}

	// If it's a getservers request
	else if (!strncmp(C2M_GETSERVERS_KPQ3, msg, strlen(C2M_GETSERVERS_KPQ3)))
	{
		HandleGetServersKPQ3(msg + strlen(C2M_GETSERVERS_KPQ3), address);
	}

	// If it's a getservers request 
	else if (!strncmp(C2M_GETSERVERS2_KPQ3, msg, strlen(C2M_GETSERVERS2_KPQ3)))
	{
		MsgPrint(MSG_DEBUG, "%s ---> getservers (%s)\n", peer_address, msg);
		HandleGetServersKPQ3(msg + strlen(C2M_GETSERVERS2_KPQ3), address);
	}


	// If it's a getmotd request
	else if (!strncmp(C2M_GETMOTD_KPQ3, msg, strlen(C2M_GETMOTD_KPQ3)))
	{
		HandleGetMotd(msg + strlen(C2M_GETMOTD_KPQ3), address);
	}
	else
	{
		MsgPrint(MSG_NORMAL, "%s ---> invalid kpq3 (%s)\n", peer_address, msg);
	}
}


/*
====================
HandleMessage

Parse a packet to figure out what to do with it
====================
*/
int HandleGspyMessage(const char *msg, const struct sockaddr_in *address)
{
	char *value;

	// If it's gamespylite request
	if (!strncmp(B2M_INITCONTACT, msg, strlen(B2M_INITCONTACT)))
	{
		HandleGetServers(msg + strlen(C2M_GETSERVERS), address, qtrue,0);
		return 1;
	}

	// old gamespy responce to request
	else if (!strncmp(B2M_GETSERVERS, msg, strlen(B2M_GETSERVERS))) //hypov8 not used anymore
	{

		// Extract the game id
		value = SearchInfostring(msg, "gamename");
		if (value == NULL)
			return 0;

		if (!(strcmp(value, "kingpin") == 0) && !(strcmp(value, "kingpinver") == 0)) //kingpinver??
		{
			MsgPrint(MSG_NORMAL, "%s ---> heartbeat (%s)\nNot Kingpin\n", peer_address, value);
			return 0;
		}
		else
			HandleGetServers(msg + strlen(C2M_GETSERVERS), address, qtrue, 0);

		return 2;
	}
	//gslist server requests. not working correct???
	else if(!strncmp(B2M_GETSERVERS_GSLIST2, msg, strlen(B2M_GETSERVERS_GSLIST2)))
	{
		const char *challenge = 0;
		char  packet[MAX_PACKET_SIZE + 1];
		char *tmp;
		//\gamename\gamespy2\gamever\20603020\enctype\0\validate\UpkV3Mfn\final\\list\cmp\gamename\kps)
		//\gamename\gamespy2\gamever\20603020\enctype\0\validate\UpkV3Mfn\final\\list\cmp\gamename\kingpin
		//kingpin            QFWxY2
		//quake2             rtW0xg


		int tcp = 1;

		memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues
		/*// Extract encrypt type    \\enctype\\0\*/
		value = SearchInfostring(msg, "enctype");
		if (value != NULL)
		{
			if (value[0] == '0')	
				tcp = 2;
		}
		//value = SearchInfostring(msg, "validate");
		//if (value != NULL)
		//	challenge = (unsigned char*)value;

		tmp = strstr(msg, "\\list\\cmp");
		value = SearchInfostring(tmp, "gamename");
		if (value != NULL)
			challenge = value;

		//nb_bytes = 
			//recv(tmpClientOut_tcp, packet, MAX_PACKET_SIZE, 0);



		HandleGetServers(msg + strlen(C2M_GETSERVERS), address, tcp, challenge);
		return 3;
	}

	MsgPrint(MSG_NORMAL, "%s ---> invalid GameSpy (%s)\n", peer_address, msg);
	return 0;
}

