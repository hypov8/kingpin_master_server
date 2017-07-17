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

////////////////
//   global   //
////////////////

// Timeouts (in secondes)
#define TIMEOUT_HEARTBEAT		320 //kingpin default 300
#define TIMEOUT_INFORESPONSE	10	//seconds

// Period of validity for a challenge string (in secondes)
#define TIMEOUT_CHALLENGE 3

//hypov8 allow a bit of time for ping responce
#define TIMEOUT_PING 5

// Maximum size of a reponse packet
#define MAX_PACKET_SIZE 1400

//hypov8 block quake 2 etc
#define KINGPIN_ONLY


////////////////
//  kp stuff  //
////////////////

// server to master
#define S2M_HEARTBEAT			"\\heartbeat\\"			//heartbeat GS packet
#define S2M_HEARTBEAT_YYYY		"ÿÿÿÿheartbeat\n"		//heartbeat game port
#define S2M_GAMENAME_KINGPIN	"\\gamename\\kingpin"	//gamename GS packet
#define S2M_SHUTDOWN_YYYY		"ÿÿÿÿshutdown"			//shutdown, server change, map etc
#define S2M_ACK_YYYY			"ÿÿÿÿack"				//recieved ack 
#define S2M_PING_YYYY			"ÿÿÿÿping"				//recieved ping (initilized server...)
#define S2M_PRINT_YYYY			"ÿÿÿÿprint\n"			//recieved print (after sending status...)
#define S2M_ERROR_STR			"Info string length exceeded\n" //fix strings to long. game port send limitation
#define S2M_FINAL				"\\final\\\\queryid\\"			//kingpin.exe responce to ack packet

// master to server
#define M2S_GETSTATUS_GS	"\\status\\"	//send status GS packet
#define M2S_GETSTATUS_YYYY	"ÿÿÿÿstatus\n"	//send status game port
#define M2S_PING_YYYY		"ÿÿÿÿping\n"	//send ping, hoping to recieve ack
#define M2S_ACK_GS			"\\ack\\"		//reponde with an ack. Gamespy
#define M2S_ACK_YYYY		"ÿÿÿÿack\n"		//reponde with an ack

//gamespy browser to master
#define B2M_INITALCONTACT		"\\gamename\\gspylite\\" //inital contact
#define B2M_GETSERVERS			"\\list\\" 
#define B2M_GETSERVERS_GSLIST2	"\\gamename\\gamespy2\\"
#define B2M_GETSERVERS_QUERY	"query"
//#define B2M_GETSERVERS_GSLIST	"\\&\\\x1\x3\\\\\\\\kingpin\\gslive\\"
//#define B2M_GETSERVERS_LIST "\\list\\\\gamename\\""
//87.175.221.101:61916 --->invalid GameSpy(\gamename\gamespy2\gamever\20603020\enctype\0\validate\Up
//kV3Mfn\final\\list\cmp\gamename\kps)
// "\x00&\x00\x01\x03\x00\x00\x00\x00kingpin\x00gslive\""

//master to gamespy browser
#define M2B_ECHOREPLY	"\\basic\\\\secure\\TXKOAT" //echo reply to gamespy

//motd
#define C2M_GETMOTD "getmotd"
#define M2C_MOTD    "motd "



////////////////
// kpq3 stuff //
////////////////

//server to master
#define S2M_HEARTBEAT_KPQ3		"heartbeat KingpinQ3-1" // "heartbeat Kingpinq3\n"
#define S2M_HEARTBEAT_DP		"heartbeat DarkPlaces"	// more accepted protocol name at other masters
#define S2M_INFORESPONSE_KPQ3	"infoResponse\x0A"		// "infoResponse\n\\pure\\1\\..."
#define S2M_FLATLINE_KPQ3		"heartbeat"				//kill kpq3 server
//#define S2M_FLATLINE			"KPQ3Flatline-1"		//kill kpq3 server

//mster to server
#define M2S_GETINFO_KPQ3		"ÿÿÿÿgetinfo "				// "getinfo A_Challenge"

//ingame browser to master
#define C2M_GETSERVERS_KPQ3		"getservers KingpinQ3-1"	// "getservers KingpinQ3-1 68 empty full"
#define C2M_GETSERVERS2_KPQ3	"getservers "				// "getservers 68 empty full"				// not using darkplaces protocol
#define C2M_GETMOTD_KPQ3		"getmotd"

//master to ingame browser
#define M2C_GETSERVERSREPONSE_KPQ3	"ÿÿÿÿgetserversResponse\\" // "getserversResponse\\...(6 bytes)...\\...(6 bytes)...\\EOT\0\0\0"
#define M2C_GETSERVERSREPONSE_Q2	"ÿÿÿÿservers " // "getserversResponse\\...(6 bytes)...\\...(6 bytes)...\\EOT\0\0\0"

#define M2C_CHALLENGE_KEY	"challenge\\"
#define M2C_MOTD_KEY		"motd\\"

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
SendGetStatus_Gamespy

Send a //status// message to a kp server on udp Gamespy port
====================
*/
static void SendGetStatus_Gamespy(const struct sockaddr_in *ServerAddress)
{
	int			netfail;
	char		msg[64] = M2S_GETSTATUS_GS;

	//gs port
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock, msg, strlen(msg), 0, (const struct sockaddr *)ServerAddress, sizeof(*ServerAddress)))
#else
	if (sendto(inSock, msg, strlen(msg), 0, (const struct sockaddr *)ServerAddress, sizeof(*ServerAddress)))
#endif
		MsgPrint(MSG_DEBUG, "%s:%hu <--- '\\\\status\\\\' Sent ( GameSpy Port )\n", inet_ntoa(ServerAddress->sin_addr), ntohs(ServerAddress->sin_port));

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_WARNING, "%s <--- '\\\\status\\\\'--== Socket Error ==-- \"%i\"\n", peer_address, netfail);
}

/*
====================
SendGetStatus

Send a "status" message on game port
inital cointact. get protocol etc..
====================
*/
static void SendGetStatus(server_t * server)
{
	int netfail;
	char            msg[64] = M2S_GETSTATUS_YYYY;
#if 0
	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		strncpy(server->challenge, BuildChallenge(), sizeof(server->challenge) - 1); //hypo not needed for kp?
		server->challenge_timeout = crt_time + TIMEOUT_CHALLENGE;
	}
#endif
	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#else
	if (sendto(inSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
		MsgPrint(MSG_DEBUG, "%s <--- 'YYYYstatus' Sent (Game Port)\n", peer_address);

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_WARNING, "%s <--- 'YYYYstatus'--== Socket Error ==-- \"%i\"\n", peer_address, netfail);
}


/*
====================
SendGetInfoKPQ3

Send a "getinfo" message to a KPQ3 server
====================
*/
static void SendGetInfoKPQ3(server_t * server)
{
	char            msg[64] = M2S_GETINFO_KPQ3;//"\xFF\xFF\xFF\xFF" M2S_GETINFO_KPQ3 " ";

	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		strncpy(server->challenge, BuildChallenge(), sizeof(server->challenge) - 1);
		server->challenge_timeout = crt_time + TIMEOUT_CHALLENGE;
	}

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);

#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_kpq3, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#else
	if (sendto(inSock_kpq3, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
	{
		MsgPrint(MSG_DEBUG, "%s <--- getinfo with challenge \"%s\"\n", peer_address, server->challenge);
	}
}

//kingpin
static void SendPing(server_t * server)
{
	int  netfail;
	char msg[64] = M2S_PING_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#else
	if (sendto(inSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
		MsgPrint(MSG_DEBUG, "%s <--- 'YYYYPing' Sent (Game Port)\n", peer_address);

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_WARNING, "%s <--- 'YYYYPing'--== Socket Error ==-- \"%i\"\n", peer_address, netfail);
}

//kingpin
static void SendAck(server_t * server)
{
	int  netfail;
	char msg[64] = M2S_ACK_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#else
	if (sendto(inSock, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
		MsgPrint(MSG_DEBUG, "%s <--- 'YYYYAck' Sent (Game Port)\n", peer_address);

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_DEBUG, "%s <--- 'YYYYAck'--== Socket Error ==-- \"%i\"\n", peer_address, netfail);

}

//kingpin on GameSpy port
static void SendAckGS(server_t * server)
{
	int  netfail;
	char msg[64] = M2S_ACK_GS;
	struct sockaddr_in tmpServerAddress;

	memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
	memcpy(&tmpServerAddress, &server->address, sizeof(tmpServerAddress));
	tmpServerAddress.sin_port = htons(server->gsPort);

#ifdef USE_ALT_OUTPORT
	if (sendto(outSock, msg, strlen(msg), 0, (struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)))
#else
	if (sendto(inSock, msg, strlen(msg), 0, (struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)))
#endif
		MsgPrint(MSG_DEBUG, "%s <--- '\\\\Ack\\\\' Sent (GameSpy Port)\n", peer_address);

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_DEBUG, "%s <--- '\\\\Ack\\\\'--== Socket Error ==-- \"%i\"\n", peer_address, netfail);

}

char *fixStringToLongError(const char* msg)
{
	int i;
	char *out;

	out = (char*)msg;
	/* fix for info strings to long in kp1 */
	for (i = 0; i < 5; i++) //loop 5 times. should be pleanty
	{
		if (!strncmp(S2M_ERROR_STR, out, strlen(S2M_ERROR_STR)))
		{
			//strcpy(out, &out[strlen(S2M_ERROR_STR)]);
			out = out + strlen(S2M_ERROR_STR);
			continue;
		}
		break;
	}
	return out;
}

/*
====================
HandleGetServersGSpy

Parse getservers requests and send the appropriate response
====================
*/
static void HandleGetServersGSpy(const struct sockaddr_in *addr, int isTCP, const char* challenge)
{
	const char     *packetheader = "";
	const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind;
	server_t       *sv;
	unsigned long    sv_addr;
	char			*char_sv_addr;
	char			tmp_packet[30];
	unsigned short  sv_port;

	qboolean		isKingpin;
	unsigned int    numServers = 0;

#ifdef KINGPIN_ONLY
	if (!(x_strcmpi(challenge, "Kingpin") == 0) &&
		!(x_strcmpi(challenge, "GameSpy") == 0) &&
		!(x_strcmpi(challenge, "KingpinQ3") == 0))
		return;
#endif	

	if (max_msg_level >= MSG_DEBUG) //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%s ---> getservers ( %s )\n", peer_address, challenge); //%d, protocol


	// Initialize the packet contents with the header
	packetind = headersize;
	memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues
	memcpy(packet, packetheader, headersize);


	// Add every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof(packet) - (7 + 6))
		{
			// End Of Transmission
			strcat(packet, "\\final\\");

			MsgPrint(MSG_DEBUG, "- Sending servers: %s\n", packet);

			// Send the packet to the client
			if (isTCP)
				sendto(tmpClientOut_tcp, packet, strlen(packet), 0, (const struct sockaddr *)addr, sizeof(*addr));
			else
				sendto(inSock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));

				
			if (max_msg_level <= MSG_NORMAL) //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%s ---> getservers ( %s ) Servers: %u\n", peer_address, challenge, numServers); //%d, protocol
			
			MsgPrint(MSG_DEBUG, "%s <--- getservers Response Gamespy (%u servers)\n", peer_address, numServers);

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
				"Comparing server: IP:\"%u.%u.%u.%u:%hu\", proto:%u, client:%hu\n",
				(int)(sv_addr >> 24), ((sv_addr >> 16) & 0xFF),
				((sv_addr >> 8) & 0xFF), (sv_addr & 0xFF), sv_port, sv->protocol, sv->nbclients);
		}

		// Check protocol, options
		isKingpin = qfalse;

		if (!x_strcmpi(challenge, "kingpin"))
		{
			isKingpin = qtrue;
			if (sv->protocol != 32)
				continue;
		}
		else if (!x_strcmpi(challenge, "quake2"))
		{
			if (sv->protocol != 34)
				continue;
		}
		else if (!x_strcmpi(challenge, "kingpinq3"))
		{
			if (!(sv->protocol == 74 || sv->protocol == 75))
				continue;
		}
		else
			continue;


		if (isTCP == 2) //gslist. send as byte
		{
			sprintf(packet, "%s%c%c%c%c%c%c", packet,
				(char)(sv_addr >> 24), (char)((sv_addr >> 16) & 0xFF),
				(char)((sv_addr >> 8) & 0xFF), (char)(sv_addr & 0xFF),
				(char)((sv_port >> 8)), (char)(sv_port & 0xFF));
			packetind += 6;
		}
		else
		{
			if( isKingpin)
				sprintf(tmp_packet, "\\ip\\%s:%i", char_sv_addr, sv->gsPort); //-10 send gamespy query port to clients
			else
				sprintf(tmp_packet, "\\ip\\%s:%i", char_sv_addr, sv_port);

			strcat(packet, tmp_packet);
			packetind += sizeof(tmp_packet);
		}
		numServers++;
	}
}


#if 1 //q2 protocol
static void HandleGetServersQuakeBrowser(const struct sockaddr_in *addr)
{
	const char     *packetheader = M2C_GETSERVERSREPONSE_Q2; //"\xFF\xFF\xFF\xFF"
	const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind;
	server_t       *sv;
	unsigned long    sv_addr;
	unsigned short  sv_port;
	unsigned int    numServers = 0;
	char			print[2048];

	if (max_msg_level >= MSG_DEBUG) //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%s ---> getservers \n", peer_address); //%d, protocol

	// Initialize the packet contents with the header
	packetind = headersize;
	memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues
	memcpy(packet, packetheader, headersize);

	memset(print, 0, sizeof(print)); //reset packet, prevent any issues

	// Add every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof(packet) - (7 + 6))
		{
			// End Of Transmission
			///////////strcat(packet, "\\final\\"); //none on quake2

			MsgPrint(MSG_DEBUG, "- Sending packet: servers %s\n", print);

			sendto(inSock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));

			if (max_msg_level <= MSG_NORMAL) //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%s ---> query.. Servers: %u\n", peer_address, numServers); //%d, protocol

			MsgPrint(MSG_DEBUG, "%s <--- getservers Response for Quake (%u servers)\n", peer_address, numServers);

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		sv_port = ntohs(sv->address.sin_port);
		sv_addr = ntohl(sv->address.sin_addr.s_addr);
		// Use the address mapping associated with the server, if any
		if (sv->addrmap != NULL)		{
			const addrmap_t *addrmap = sv->addrmap;

			sv_addr = ntohl(addrmap->to.sin_addr.s_addr);
			if (addrmap->to.sin_port != 0)
				sv_port = ntohs(addrmap->to.sin_port);
		}

		// Extra debugging info
		if (max_msg_level >= MSG_DEBUG)		{
			MsgPrint(MSG_DEBUG,
				"Comparing server: IP:\"%u.%u.%u.%u:%hu\", proto:%u, client:%hu\n",
				(int)(sv_addr >> 24), (int)((sv_addr >> 16) & 0xFF),
				(int)((sv_addr >> 8) & 0xFF), (int)(sv_addr & 0xFF),
				sv_port, sv->protocol, sv->nbclients);
		}

		//hypov8 allow kp1 + q2 servers in game browser. 
		if (sv->protocol != 32 && sv->protocol != 34)
			continue;


		sprintf(print, "%s\\%u.%u.%u.%u:%hu\\", print,
			(char)(sv_addr >> 24), (char)((sv_addr >> 16) & 0xFF),
			(char)((sv_addr >> 8) & 0xFF), (char)(sv_addr & 0xFF),
			sv_port);

		// IP address
		packet[packetind] = sv_addr >> 24;
		packet[packetind + 1] = (sv_addr >> 16) & 0xFF;
		packet[packetind + 2] = (sv_addr >> 8) & 0xFF;
		packet[packetind + 3] = sv_addr & 0xFF;

		// Port
		packet[packetind + 4] = sv_port >> 8;
		packet[packetind + 5] = sv_port & 0xFF;
		packetind += 6;
		
		numServers++;
	}
}
#endif


/*
====================
HandleGetServersKPQ3

Parse getservers requests and send the appropriate response
====================
*/
static void HandleGetServersKPQ3(const char *msg, const struct sockaddr_in *addr)
{
	const char     *packetheader = M2C_GETSERVERSREPONSE_KPQ3; //"\xFF\xFF\xFF\xFF" M2C_GETSERVERSREPONSE_KPQ3 "\\";
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

	// hypo must exist to show all servers
	no_empty = (strstr(msg, "empty") == NULL);
	no_full =  (strstr(msg, "full") == NULL);

	// Initialize the packet contents with the header
	packetind = headersize;
	// hypo zero packet
	memset(packet, 0, sizeof(packet));
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

			MsgPrint(MSG_DEBUG, "%s <--- getservers Response for KingpinQ3 (%u servers)\n", peer_address, numServers);

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
			continue;	// Skip it

		// Use the address mapping associated with the server, if any
		if (sv->addrmap != NULL)
		{
			const addrmap_t *addrmap = sv->addrmap;

			sv_addr = ntohl(addrmap->to.sin_addr.s_addr);
			if (addrmap->to.sin_port != 0)
				sv_port = ntohs(addrmap->to.sin_port);

			MsgPrint(MSG_DEBUG,	"Server address mapped to %u.%u.%u.%u:%hu\n",
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

#if 0
		MsgPrint(MSG_DEBUG, "- Sending server %u.%u.%u.%u:%hu\n", 
			(qbyte)packet[packetind], (qbyte)packet[packetind + 1],
			(qbyte)packet[packetind + 2], (qbyte)packet[packetind + 3], sv_port);
#else
		MsgPrint(MSG_DEBUG, "- Sending server: %s\n", packet);
#endif
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
#if 0
static void HandleInfoResponse(server_t * server, const char *msg)//hypo todo: use this for messages
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
	server->timeout = crt_time + TIMEOUT_HEARTBEAT;
}
#endif

/*
====================
HandleInfoResponseKPQ3

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
		MsgPrint(MSG_ERROR, "%s ---> ERROR: invalid challenge=%s(%s)\n", peer_address, value, server->challenge);
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
	server->timeout = crt_time + TIMEOUT_HEARTBEAT;
}


/*
====================
HandleGetMotd

Parse getservers requests and send the appropriate response
====================
*/
static void HandleGetMotd(const char *msg, const struct sockaddr_in *addr) //hypov8 todo: text file?
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

	strncpy(&packet[packetind], M2C_CHALLENGE_KEY, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(M2C_CHALLENGE_KEY);

	strncpy(&packet[packetind], challenge, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(challenge);
	packet[packetind++] = '\\';

	strncpy(&packet[packetind], M2C_MOTD_KEY, MAX_PACKET_SIZE - packetind - 2);
	packetind += strlen(M2C_MOTD_KEY);

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
	server_t					*server;
	char						*value;
	struct sockaddr_in	tmpServerAddress;

//Gamespy  //heartbeat//31500//gamename//kingpin
	if(!strncmp(S2M_HEARTBEAT, msg, strlen(S2M_HEARTBEAT)))
	{
		char *port, *gamename;

		// Extract the game id
		gamename = SearchInfostring(msg, "gamename");
		if (gamename == NULL)	{
			MsgPrint(MSG_DEBUG, "%s Heartbeat ---> @%lld No GameName\n", peer_address, crt_time);
			return;		
		}
#ifdef KINGPIN_ONLY
		if (!(x_strcmpi(gamename, "kingpin") == 0)) {
			MsgPrint(MSG_NORMAL, "%s ---> @%lld heartbeat (%s)\nNot Kingpin\n", peer_address, crt_time, gamename);
			return;		
		}
#endif
		port = SearchInfostring(msg, "heartbeat"); //port
		if (port == NULL) {
			MsgPrint(MSG_DEBUG, "%s ---> @%lld No port in HeartBeat\n", peer_address, crt_time);
			return;		
		}

		/* copy to tmp. dont store server */
		memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
		memcpy(&tmpServerAddress, address, sizeof(tmpServerAddress));

		/* send //status// on port found in string. initial contact is random port */
		/* it looks like this is used to make sure gamespy port is open */
		tmpServerAddress.sin_port = htons((u_short)atoi(port));

		MsgPrint(MSG_DEBUG, "%s ---> @%lld \\\\Heartbeat\\\\\n", peer_address, crt_time);

		/* get more info before storing server */
		SendGetStatus_Gamespy((const struct sockaddr_in*)&tmpServerAddress); //status//
	}
//gamespy //gamename//kingpin//
	else if (!strncmp(S2M_GAMENAME_KINGPIN, msg, strlen(S2M_GAMENAME_KINGPIN)))
	{
		char *gamePort;
		char *protocol;
		char *msgTrimmed;
		u_short tmp;

		msgTrimmed = (char*)msg + strlen(S2M_GAMENAME_KINGPIN);
		msgTrimmed = fixStringToLongError(msgTrimmed); //shouldent need for GS?

		// Extract the game id
		value = SearchInfostring((const char*)msgTrimmed, "protocol");
		if (value == NULL) {
			MsgPrint(MSG_NORMAL, "%s ---> No protocol in game string\n", peer_address);
			return;
		}
		protocol = x_strdup(value);

#ifdef KINGPIN_ONLY
		if (!(strcmp(protocol, "32") == 0)) {
			MsgPrint(MSG_NORMAL, "%s ---> @%lld protocol (%s)\nNot Kingpin\n", peer_address, crt_time, protocol);
			return;
		}
#endif
		// Extract hostport
		value = SearchInfostring((const char*)msgTrimmed, "hostport");
		if (value == NULL) {
			MsgPrint(MSG_NORMAL, "%s ---> No hostport in game string\n", peer_address);
			return;
		}
		gamePort = x_strdup(value);
		tmp = ntohs(address->sin_port);

		memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
		memcpy(&tmpServerAddress, address, sizeof(tmpServerAddress));
		tmpServerAddress.sin_port = htons((u_short)atoi(gamePort));

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr((const struct sockaddr_in*)&tmpServerAddress, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%s ---> @%lld '\\\\gamename\\\\kingpin' No Server\n", peer_address, crt_time);
			return;
		}

		server->gsPort = tmp;
		server->active = qtrue;
		server->protocol = atoi(protocol);
		MsgPrint(MSG_DEBUG, "%s ---> @%lld '\\\\gamename\\\\kingpin\\' \n", peer_address, crt_time);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;

		//hypo reply to server. acknowledge packet recieved
		SendAckGS(server); //ToDo: check gs? 
	}
// responce to ack  //final////queryid//
	else if (!strncmp(S2M_FINAL, msg, strlen(S2M_FINAL)))
	{
		//do nothing
		MsgPrint(MSG_DEBUG, "%s --->  //final//queryid kp1\n", peer_address);
	}
//end Gamespy packets





//Quake  yyyyHeartbeat\n
	else if (!strncmp(S2M_HEARTBEAT_YYYY, msg, strlen(S2M_HEARTBEAT_YYYY)))
	{
		char *protocol, *msgTrimmed;

		/*minus YYYYheartbeat\n*/
		msgTrimmed = (char*)msg + strlen(S2M_HEARTBEAT_YYYY);
		msgTrimmed = fixStringToLongError(msgTrimmed);

		// Extract the game id
		protocol = SearchInfostring((const char*)msgTrimmed, "protocol");
		if (protocol == NULL)		{
			MsgPrint(MSG_NORMAL, "%s ---> No protocol in game string\n", peer_address);
			return;
		}

#ifdef KINGPIN_ONLY
		if (!(strcmp(protocol, "32")) == 0)	{
			MsgPrint(MSG_NORMAL, "%s ---> Protocol not 32\n", peer_address); //hypo force kingpin only?
			return;
		}
#endif	
		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYHeartbeat No' Server\n", peer_address, crt_time);
			return;	
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port )- (u_short)10 ;

		server->active = qtrue;
		server->protocol = atoi(protocol);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYHeartbeat' \n", peer_address, crt_time);

		//hypo reply to server. acknowledge packet recieved
		SendAck(server);
	}

//Quake yyyyprint\n
	else if ((!strncmp(S2M_PRINT_YYYY, msg, strlen(S2M_PRINT_YYYY))))
	{
		char *protocol, *msgTrimmed;

		// remove YYYYprint\n
		msgTrimmed = (char*)msg + strlen(S2M_PRINT_YYYY);
		msgTrimmed = fixStringToLongError(msgTrimmed);

		// Extract the game id
		protocol = SearchInfostring(msgTrimmed, "protocol");
		if (protocol == NULL)		{
			MsgPrint(MSG_NORMAL, "%s ---> No protocol in game string\n", peer_address);
			return;	
		}

#ifdef KINGPIN_ONLY
		if (!(strcmp(protocol, "32"))==0)	{
			MsgPrint(MSG_NORMAL, "%s ---> Game is not protocol 32\n", peer_address);
			return;	
		}
#endif
		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYPrint' No Server\n", peer_address, crt_time);
			return;		
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

		server->active = qtrue;
		server->protocol = atoi(protocol);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		MsgPrint(MSG_DEBUG, "%s ---> @%lld 'yyyyprint' \n", peer_address, crt_time);

		//hypo reply to server. acknowledge packet recieved
		SendAck(server);
	}
//Quake  yyyyshutdow. check if status changed or quit
	else if (!strncmp(S2M_SHUTDOWN_YYYY, msg, strlen(S2M_SHUTDOWN_YYYY)))
	{
		/* check for a valid server */
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
		{	//hypov8 server did not send initial heartbeat. add it
			server = Sv_GetByAddr(address, qtrue);
			if (server == NULL) {
				MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYShutDown' No Server\n", peer_address, crt_time);
				return;
			}
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			MsgPrint(MSG_DEBUG, "%s --->  @%lld 'YYYYShutdown' \n", peer_address, crt_time);
			SendGetStatus(server);
			return;
		}

		server->timeout = crt_time + TIMEOUT_PING;
		MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYShutdown' \n", peer_address, crt_time);

		/* check if server is active or shutdown */
		SendPing(server);
	}
//server sent ack. keep active. do we need to check if status changed?
	else if (!strncmp(S2M_ACK_YYYY, msg, strlen(S2M_ACK_YYYY)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYAck' No Server\n", peer_address, crt_time);
			return;		
		}

		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
	}
//server sent ping
	else if (!strncmp(S2M_PING_YYYY, msg, strlen(S2M_PING_YYYY)))
	{
		/* check for a valid server */
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL) 
		{	//hypov8 server didnt send initial heartbeat. add it
			server = Sv_GetByAddr(address, qtrue);
			if (server == NULL)
			{
				MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYPing' No Server\n", peer_address, crt_time);
				return;	
			}

			//hypo have to assume gamespy port.
			if (!server->gsPort)
				server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			MsgPrint(MSG_DEBUG, "%s --->  @%lld 'YYYYPing' New Server", peer_address, crt_time);
			SendGetStatus(server);
			return;
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		MsgPrint(MSG_DEBUG, "%s ---> @%lld 'YYYYping' \n", peer_address, crt_time);
		if (!server->protocol){
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			SendGetStatus(server);
		}
		else
			SendAck(server);
	}
//client to master. getmotd request. ToDo: motd
	else if(!strncmp(C2M_GETMOTD, msg, strlen(C2M_GETMOTD)))
	{
		MsgPrint(MSG_DEBUG, "%s ---> @%lld getmoto kp1\n", peer_address, crt_time);
		HandleGetMotd(msg + strlen(C2M_GETMOTD), address);
	}
//quake2 master query..	
	else if (!strncmp(B2M_GETSERVERS_QUERY, msg, strlen(B2M_GETSERVERS_QUERY)))
	{
		HandleGetServersQuakeBrowser(address);
		MsgPrint(MSG_DEBUG, "%s ---> Request Q2 server packet \n", peer_address);
	}
//error
	else
	{
		MsgPrint(MSG_NORMAL, "%s ---> invalid packet (%s)\n", peer_address, msg);
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
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;

		// Ask for some info
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
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;

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

// If it's a shutdown request
	else if (!strncmp(S2M_FLATLINE_KPQ3, msg, strlen(S2M_FLATLINE_KPQ3)))
	{
		if (strstr(msg, "Flatline") != 0)
		{
			server = Sv_GetByAddr(address, qfalse);
			if (server == NULL)
				return;
			server->timeout = crt_time /*+ TIMEOUT_CHALLENGE*/; //remove server
		}
	}
// invalid
	else 
		MsgPrint(MSG_NORMAL, "%s ---> invalid kpq3 (%s)\n", peer_address, msg);

}


/*
====================
HandleMessage
TCP
Parse a packet to figure out what to do with it
====================
*/
void HandleGspyMessage(const char *msg, const struct sockaddr_in *address)
{
	char *value;
	const char *challenge = NULL;
	char *tmp;
	int tcp = 1;

// If it's gamespylite inital request
	if (!strncmp(B2M_INITALCONTACT, msg, strlen(B2M_INITALCONTACT)))
	{
		HandleGetServersGSpy(address, qtrue, "GameSpy");
		MsgPrint(MSG_DEBUG, "Sent GamespyLite Packet\n");
	}
// old gamespy responce to request. //list//
	else if (!strncmp(B2M_GETSERVERS, msg, strlen(B2M_GETSERVERS))) 
	{ // \list\\gamename\kingpinver\01\location\0\validate\LO/WUC4c\final\\queryid\1.1

		/* Extract the game id */
		tmp = strstr(msg, "\\gamename");

		challenge = SearchInfostring((const char*)tmp, "gamename");
		if (challenge != NULL)
		{
			MsgPrint(MSG_DEBUG, "%s ---> B2M \\list\\ (%s)\n", peer_address, challenge);
			HandleGetServersGSpy(address, qtrue, challenge);
			MsgPrint(MSG_DEBUG, "Sent GamespyLite Packet\n");
		}
		else
			MsgPrint(MSG_DEBUG, "INVALID: gamename\n");

	}
//gslist server requests.
	else if(!strncmp(B2M_GETSERVERS_GSLIST2, msg, strlen(B2M_GETSERVERS_GSLIST2)))
	{	//\gamename\gamespy2\gamever\20603020\enctype\0\validate\UpkV3Mfn\final\\list\cmp\gamename\kps)
		//\gamename\gamespy2\gamever\20603020\enctype\0\validate\UpkV3Mfn\final\\list\cmp\gamename\kingpin
		//kingpin            QFWxY2
		//quake2             rtW0xg

		/* Extract encrypt type    \\enctype\\0\ */
		value = SearchInfostring(msg, "enctype");
		if (value != NULL)
		{
			if (value[0] == '0')
				tcp = 2;
		}

		tmp = strstr(msg, "\\list\\cmp");
		challenge = SearchInfostring((const char*)tmp, "gamename");
		if (challenge != NULL)
		{
			HandleGetServersGSpy(address, tcp, challenge);
			MsgPrint(MSG_DEBUG, "Sent GSLite Packet\n");
		}
		else
			MsgPrint(MSG_DEBUG, "INVALID: gamename\n");
	}
	else //error
	{
		MsgPrint(MSG_NORMAL, "%s ---> invalid GameSpy (%s)\n", peer_address, msg);
		printf("ERROR: NOT GamespyLite Packet\n");

	}
}


qboolean IsGameSpyPacket(const char *msg)
{
	char *value;
	value = strstr(msg, "\\list\\");
	if (value)
		return 0;

	// If it's gamespylite request
	if (!strncmp(B2M_INITALCONTACT, msg, strlen(B2M_INITALCONTACT)) ||
		!strncmp(B2M_GETSERVERS_GSLIST2, msg, strlen(B2M_GETSERVERS_GSLIST2)))
		return qtrue;

	return qfalse;

}
