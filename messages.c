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
//common


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
	char		tmpIP[128];

	//gs port
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock, msg, strlen(msg), 0, (const struct sockaddr *)ServerAddress, sizeof(*ServerAddress)))
#else
	if (sendto(inSock_udp, msg, strlen(msg), 0, (const struct sockaddr *)ServerAddress, sizeof(*ServerAddress)))
#endif
	{
		//	sprintf(tmp, "%s:%hu",inet_ntoa(ServerAddress->sin_addr), ntohs(ServerAddress->sin_port));
		snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", inet_ntoa(ServerAddress->sin_addr), ntohs(ServerAddress->sin_port));
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (GameSpy Port) \n", tmpIP, "'\\\\status\\\\'");
	}

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s --== Socket Error ==-- \"%i\"\n", peer_address, "'\\\\status\\\\'", netfail);
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
	if (sendto(inSock_udp, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (Game Port) \n", peer_address, "'YYYYstatus'");

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n", peer_address, "'YYYYstatus'", netfail);
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
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s challenge(%s) \n", peer_address, "'getinfo'", server->challenge);
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
	if (sendto(inSock_udp, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (Game Port) \n", peer_address, "'YYYYPing'");

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n", peer_address, "'YYYYPing'", netfail);
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
	if (sendto(inSock_udp, msg, strlen(msg), 0, (struct sockaddr *)&server->address, sizeof(server->address)))
#endif
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (Game Port) \n", peer_address, "'YYYYAck'");

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n", peer_address, "'YYYYAck'", netfail);

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
	if (sendto(inSock_udp, msg, strlen(msg), 0, (struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)))
#endif
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (GameSpy Port)\n", peer_address, "'\\\\Ack\\\\'");

	netfail = ERRORNUM;
	if (netfail)
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n", peer_address, "'\\\\Ack\\\\'", netfail);

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
static void HandleGetServersGSpy(const struct sockaddr_in *addr, int isTCP, const char* challenge, SOCKET_NET tmpSoc)
{
	//const char     *packetheader = "\0";
	//const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind=0;
	server_t       *sv;
	unsigned long    sv_addr;
	char			*char_sv_addr;
	char			tmp_packet[30];
	unsigned short  sv_port;

	qboolean		isKingpin;
	unsigned int    numServers = 0;

#if 0 //def KINGPIN_ONLY
	if (!(x_strcmpi(challenge, "Kingpin") == 0) &&
		!(x_strcmpi(challenge, "GameSpy") == 0) &&
		!(x_strcmpi(challenge, "KingpinQ3") == 0)&&
		!(x_strcmpi(challenge, "KingpinQ3-1") == 0))
		return;
#endif	

	if (max_msg_level >= MSG_DEBUG) //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s (%s) \n", peer_address, "'getservers'", challenge); //%d, protocol


	// Initialize the packet contents with the header
	memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues


	// Add every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof(packet) - (7 + 6))
		{
			// End Of Transmission
			strcat(packet, "\\final\\");
			packetind += 7;

			MsgPrint(MSG_DEBUG, "%-21s <--- Sending servers: %s\n", peer_address, packet);

			// Send the packet to the client
			if (isTCP)
				sendto(tmpSoc, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
			else
				sendto(inSock_udp, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));

				
			if (max_msg_level <= MSG_NORMAL) { //hypov8 print if no debug 
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "%s (%s)", "getservers", challenge );
				if (isTCP==2)
					MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %u (GL)\n", peer_address, tmp, numServers); //%d, protocol
				else
					MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %u (GS)\n", peer_address, tmp, numServers); //%d, protocol
			}

			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s (Gamespy) (%u servers)\n", peer_address, "getservers Response", numServers);

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = 0;
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
		else if (!x_strcmpi(challenge, "kingpinq3")|| !x_strcmpi(challenge, "kingpinq3-1"))
		{

			if (!(sv->protocol == 74 || sv->protocol == 75) ||
				x_strcmpi(sv->gamename, "kingpinq3-1"))
				continue;
		}
		else
			continue;


		if (isTCP == 2) //gslist. send as byte
		{
#if 0
			sprintf(packet, "%s%c%c%c%c%c%c", packet,
				(char)(sv_addr >> 24), (char)((sv_addr >> 16) & 0xFF),
				(char)((sv_addr >> 8) & 0xFF), (char)(sv_addr & 0xFF),
				(char)((sv_port >> 8)), (char)(sv_port & 0xFF));
			packetind += 6;
#else
			// IP address
			packet[packetind] = sv_addr >> 24;
			packet[packetind + 1] = (sv_addr >> 16) & 0xFF;
			packet[packetind + 2] = (sv_addr >> 8) & 0xFF;
			packet[packetind + 3] = sv_addr & 0xFF;

			// Port
			packet[packetind + 4] = sv_port >> 8;
			packet[packetind + 5] = sv_port & 0xFF;
			packetind += 6;
#endif
		}
		else
		{
			if( isKingpin)
				sprintf(tmp_packet, "\\ip\\%s:%i", char_sv_addr, sv->gsPort); //-10 send gamespy query port to clients
			else
				sprintf(tmp_packet, "\\ip\\%s:%i", char_sv_addr, sv_port);

			strcat(packet, tmp_packet);
			packetind += strlen(tmp_packet);
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
		MsgPrint(MSG_NORMAL, "%-21s ---> getservers \n", peer_address); //%d, protocol

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

			sendto(inSock_udp, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));

			if (max_msg_level <= MSG_NORMAL) //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %u (GB)\n", peer_address, "getservers (quake)", numServers); //%d, protocol

			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Quake (%u servers)\n", peer_address, "getservers Response", numServers);

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
			(int)(sv_addr >> 24), (int)((sv_addr >> 16) & 0xFF),
			(int)((sv_addr >> 8) & 0xFF), (int)(sv_addr & 0xFF),
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
	char			gamename[64] = "";
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind;
	server_t       *sv;
	unsigned int    protocol;
	char			*char_sv_addr = ""; //add hypov8
	char			printStr[MAX_PACKET_SIZE*2];	//add hypo
	unsigned int    sv_addr;
	unsigned short  sv_port;
	qboolean        no_empty;
	qboolean        no_full;
	unsigned int    numServers = 0;

//	unsigned int    tmp6 = 0;
//	byte one1, one2;

	//MsgPrint(MSG_NORMAL, "%s \n", packet);

	// Check if there's a name before the protocol number
	// In this case, the message comes from a DarkPlaces-compatible client
	protocol = atoi(msg);
	if (!protocol)
	{
		char *space;

		strncpy(gamename, msg, sizeof(gamename) - 1);
		gamename[sizeof(gamename) - 1] = '\0';
		space = strchr(gamename, ' ');
		if (space)
			*space = '\0';
		msg += strlen(gamename) + 1;

		protocol = atoi(msg);
	}
	// Else, it comes from a Quake III Arena client
	else
	{
		strncpy(gamename, S2M_FLATLINE_KPQ3, sizeof(gamename) - 1);
		gamename[sizeof(gamename) - 1] = '\0';
	}


	if (max_msg_level >= MSG_DEBUG) //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s kingpinQ3 (P:%d) \n", peer_address, "'getservers'", protocol);

	// hypo must exist to show all servers
	no_empty = (strstr(msg, "empty") == NULL);
	no_full =  (strstr(msg, "full") == NULL);

	// Initialize the packet contents with the header
	packetind = headersize;
	// hypo zero packet
	memset(printStr, 0, sizeof(printStr));
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
			sendto(inSock_udp, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
			
			if (max_msg_level <= MSG_NORMAL) //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %i (GB)(P:%d)\n", peer_address, "getservers (kingpinQ3)", numServers, protocol);

			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s KingpinQ3 (%u servers)\n", peer_address, "getservers Response", numServers);
			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s (packet:' %s ') \n\n", peer_address,"Sending servers", packet);
			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s (packet:' %s ') \n\n", peer_address,"Sending servers", printStr);

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		char_sv_addr = inet_ntoa(sv->address.sin_addr);
		sv_addr = ntohl(sv->address.sin_addr.s_addr);
		sv_port = ntohs(sv->address.sin_port);

		// Extra debugging info
		if (max_msg_level >= MSG_DEBUG)
		{
			MsgPrint(MSG_DEBUG,
				"Comparing server: IP:\"%u.%u.%u.%u:%hu\"  (p:%u, c:%hu)\n",
				sv_addr >> 24, (sv_addr >> 16) & 0xFF,
				(sv_addr >> 8) & 0xFF, sv_addr & 0xFF, sv_port, sv->protocol, sv->nbclients);

			if (sv->protocol != protocol)
				MsgPrint(MSG_DEBUG, "Reject: protocol %u \n", sv->protocol);
			if (sv->nbclients == 0 && no_empty)
				MsgPrint(MSG_DEBUG, "Reject: No clients  (%hu/%hu)\n", sv->nbclients, sv->maxclients);
			if (sv->nbclients == sv->maxclients && no_full)
				MsgPrint(MSG_DEBUG, "Reject: Max clients (%hu/%hu) \n", sv->nbclients, sv->maxclients);
		}

		// Check protocol, options
		if (sv->protocol != protocol || (sv->nbclients == 0 && no_empty) || (sv->nbclients == sv->maxclients && no_full))
			continue;	// Skip it

		// Use the address mapping associated with the server, if any
		if (sv->addrmap != NULL)
		{
			const addrmap_t *addrmap = sv->addrmap;
			char_sv_addr = inet_ntoa(sv->address.sin_addr);

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
		//hypo todo: packet change to string
		MsgPrint(MSG_DEBUG, "- Sending server %u.%u.%u.%u:%hu\n", 
			(qbyte)packet[packetind], (qbyte)packet[packetind + 1],
			(qbyte)packet[packetind + 2], (qbyte)packet[packetind + 3], sv_port);
#else
		//MsgPrint(MSG_DEBUG, "- Sending server: %s\n", packet);

		sprintf(printStr, "%s/ip/%s:%hu", printStr, char_sv_addr, sv_port);
#endif
		packetind += 7;
		numServers++;
	}

}


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

	MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'infoResponse'");

	// Check the challenge
	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		MsgPrint(MSG_WARNING, "%-21s ---> %-22s Obsolete challenge \n", peer_address, "WARNING: 'infoResponse'");
		return;
	}
	value = SearchInfostring(msg, "challenge");
	if (!value || strcmp(value, server->challenge))
	{
		MsgPrint(MSG_WARNING, "%-21s ---> %-22s Invalid challenge \n", peer_address, "WARNING: 'infoResponse'"); // , value, server->challenge);
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
		MsgPrint(MSG_WARNING,"%-21s ---> %-22s Invalid (protocol: %d, maxclients: %d) \n",
			peer_address, "WARNING: 'infoResponse'", new_protocol, new_maxclients);
		return;
	}
	server->protocol = new_protocol;
	server->maxclients = new_maxclients;

	// Save some other useful values
	value = SearchInfostring(msg, "clients");
	if (value)
		server->nbclients = (unsigned short)atoi(value);

	value = SearchInfostring(msg, "gamename");
	if (value == NULL)
	{
		value = S2M_FLATLINE_KPQ3;	// Q3A doesn't send a gamename, so we add it manually
		MsgPrint(MSG_WARNING, "%-21s ---> %-22s Invalid gamename\n", peer_address, "WARNING: 'infoResponse'");
	}

	// If the gamename has changed
	if (strcmp(server->gamename, value))
	{
		if (strcmp(server->gamename ,""))
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Changed (%s to %s) \n",
				peer_address, "Server gamename", server->gamename, value);

		strncpy(server->gamename, value, sizeof(server->gamename) - 1);
	}

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
	const char     *packetheader = YYYY M2C_MOTD;//"\"";
	const size_t    headersize = strlen(packetheader);
	char            packet[MAX_PACKET_SIZE];
	char            challenge[MAX_PACKET_SIZE];
	const char     *motd = "";	//FIXME
	size_t          packetind;
	char           *value;
	char            version[1024], renderer[1024];

	MsgPrint(MSG_DEBUG, "%-21s ---> getmotd \n", peer_address);

	value = SearchInfostring(msg, "challenge");
	if(!value)
	{
		MsgPrint(MSG_ERROR, "%-21s ---> ERROR: invalid challenge (%s) \n", peer_address, value);
		return;
	}

	strncpy(challenge, value, sizeof(challenge) - 1);
	challenge[sizeof(challenge) - 1] = '\0';

	value = SearchInfostring(msg, "renderer");
	if(value)
	{
		strncpy(renderer, value, sizeof(renderer) - 1);
		renderer[sizeof(renderer) - 1] = '\0';
		MsgPrint(MSG_DEBUG, "%-21s ---> is using renderer %s\n", peer_address, value);
	}

	value = SearchInfostring(msg, "version");
	if(value)
	{
		strncpy(version, value, sizeof(version) - 1);
		version[sizeof(version) - 1] = '\0';
		MsgPrint(MSG_DEBUG, "%-21s ---> is using version %s \n", peer_address, value);
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

	MsgPrint(MSG_DEBUG, "%-21s <--- motd\n", peer_address);

	// Send the packet to the client
	sendto(inSock_udp, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
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
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No GameName \n", peer_address, "'\\Heartbeat\\'");
			return;		
		}
#ifdef KINGPIN_ONLY
		if (!(x_strcmpi(gamename, "kingpin") == 0)) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Not Kingpin (%s) \n", peer_address, "'\\heartbeat\\'", gamename);
			return;		
		}
#endif
		port = SearchInfostring(msg, "heartbeat"); //port
		if (port == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No port \n", peer_address, "'\\HeartBeat\\'");
			return;		
		}

		/* copy to tmp. dont store server */
		memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
		memcpy(&tmpServerAddress, address, sizeof(tmpServerAddress));

		/* send //status// on port found in string. initial contact is random port */
		/* it looks like this is used to make sure gamespy port is open (no firewall) */
		tmpServerAddress.sin_port = htons((u_short)atoi(port));

		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'\\\\Heartbeat\\\\'");

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
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No protocol \n", peer_address, "'\\\\gamename\\\\kingpin'");
			return;
		}
		protocol = x_strdup(value);

#ifdef KINGPIN_ONLY
		if ((strcmp(protocol, "32"))) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Not Kingpin protocol (%s) \n", peer_address, "'\\\\gamename\\\\kingpin'", protocol);
			return;
		}
#endif
		
		// Extract "private"
		value = SearchInfostring((const char*)msgTrimmed, "private");
		if (value && atoi(value)==1){
			MsgPrint(MSG_NORMAL, "%-21s ---> IS PRIVATE \n", peer_address);
			return;
		}

		// Extract hostport
		value = SearchInfostring((const char*)msgTrimmed, "hostport");
		if (value == NULL) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No hostport \n", peer_address, "'\\\\gamename\\\\kingpin'");
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
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server \n", peer_address, "'\\\\gamename\\\\kingpin'");
			return;
		}

		server->gsPort = tmp;
		server->active = qtrue;
		server->protocol = atoi(protocol);
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s Saved (GameSpy port) \n", peer_address, "'\\\\gamename\\\\kingpin\\'");
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;

		//hypo reply to server. acknowledge packet recieved
		SendAckGS(server); //ToDo: check gs? 
	}
// responce to ack  //final////queryid//
	else if (!strncmp(S2M_FINAL, msg, strlen(S2M_FINAL)))
	{
		//do nothing
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s kingpin.exe\n", peer_address, "'\\\\final\\\\queryid\\\\'");
	}
//end Gamespy packets





//Quake  yyyyHeartbeat\n
	else if (!strncmp(S2M_HEARTBEAT_YYYY, msg, strlen(S2M_HEARTBEAT_YYYY)))
	{
		char *protocol, *msgTrimmed;

		/*minus YYYYheartbeat\n*/
		msgTrimmed = (char*)msg + strlen(S2M_HEARTBEAT_YYYY);
		msgTrimmed = fixStringToLongError(msgTrimmed);

		// Extract "private"
		value = SearchInfostring((const char*)msgTrimmed, "private");
		if (value && atoi(value) == 1){
			MsgPrint(MSG_NORMAL, "%-21s ---> IS PRIVATE \n", peer_address);
			return;
		}

		// Extract the game id
		protocol = SearchInfostring((const char*)msgTrimmed, "protocol");
		if (protocol == NULL)		{
#ifndef KINGPIN_ONLY
			protocol = "34"; //set q2 protocol if missing
#else
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No protocol \n", peer_address, "'YYYYHeartbeat'");
	//		return;
#endif
		}

#ifdef KINGPIN_ONLY
		if (!(strcmp(protocol, "32")) == 0)	{
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Protocol not 32\n", peer_address, "'YYYYHeartbeat'"); //hypo force kingpin only?
			return;
		}
#endif	


		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "'YYYYHeartbeat'");
			return;	
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port )- (u_short)10 ;

		server->active = qtrue;
		server->protocol = atoi(protocol);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'YYYYHeartbeat'");

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

		// Extract "private"
		value = SearchInfostring((const char*)msgTrimmed, "private");
		if (value && atoi(value) == 1){
			MsgPrint(MSG_NORMAL, "%-21s ---> IS PRIVATE \n", peer_address);
			return;
		}

		// Extract the game id
		protocol = SearchInfostring(msgTrimmed, "protocol");
		if (protocol == NULL)		{
#ifndef KINGPIN_ONLY
			protocol = "34";
#else
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No protocol \n", peer_address, "'YYYYprint'");
			return;	
#endif
		}

#ifdef KINGPIN_ONLY
		if (!(strcmp(protocol, "32"))==0)	{
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Not protocol 32 \n", peer_address, "'YYYYprint'");
			return;	
		}
#endif
		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server \n", peer_address, "'YYYYprint'");
			return;		
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

		server->active = qtrue;
		server->protocol = atoi(protocol);
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'YYYYprint'");

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
				MsgPrint(MSG_DEBUG, "%-21s ---> '%-22s No Server\n", peer_address, "'YYYYShutdown'");
				return;
			}
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			server->isWaitResponce = qtrue;
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s add server\n", peer_address, "'YYYYShutdown'");
			SendGetStatus(server);
			return;
		}

		server->timeout = crt_time + TIMEOUT_PING;
		server->isWaitResponce = qtrue;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'YYYYShutdown'");

		/* check if server is active or shutdown */
		SendPing(server);
	}
//server sent ack. keep active. do we need to check if status changed?
	else if (!strncmp(S2M_ACK_YYYY, msg, strlen(S2M_ACK_YYYY)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "'YYYYAck'");
			return;		
		}

		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
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
				MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "'YYYYPing'");
				return;	
			}

			//hypo have to assume gamespy port.
			if (!server->gsPort)
				server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			server->isWaitResponce = qtrue;
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s New Server \n", peer_address, "'YYYYPing'");
			SendGetStatus(server);
			return;
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'YYYYPing'");

		if (!server->protocol){
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			server->isWaitResponce = qtrue;
			SendGetStatus(server);
		}
		else
			SendAck(server);
	}
//client to master. getmotd request. ToDo: motd
	else if(!strncmp(C2M_GETMOTD, msg, strlen(C2M_GETMOTD)))
	{
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s kp1\n", peer_address, "'getmoto'");
		HandleGetMotd(msg + strlen(C2M_GETMOTD), address);
	}
//quake2 master query..	
	else if (!strncmp(B2M_GETSERVERS_QUERY, msg, strlen(B2M_GETSERVERS_QUERY)))
	{
		HandleGetServersQuakeBrowser(address);
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s Request quake server packet \n", peer_address, "'query..'");
	}
//error
	else
	{
		MsgPrint(MSG_NORMAL, "%-21s ---> Invalid packet!!!     (%s) \n", peer_address, msg);
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
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'heartbeat Darkplaces'"/*, gameId*/);

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
		server->isWaitResponce = qtrue;
		
		// Ask for some info
		SendGetInfoKPQ3(server);
	}

// If it's an heartbeat (old name kpq3)
	else if (!strncmp(S2M_HEARTBEAT_KPQ3, msg, strlen(S2M_HEARTBEAT_KPQ3)))
	{
		char            gameId[64];

		// Extract the game id
		sscanf(msg + strlen(S2M_HEARTBEAT_KPQ3) + 1, "%63s", gameId);
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "'heartbeat KingpinQ3-1'"/*, gameId*/);

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
		server->isWaitResponce = qtrue;

		// Ask for some infos
		SendGetInfoKPQ3(server);
	}

// If it's an infoResponse message
	else if (!strncmp(S2M_INFORESPONSE_KPQ3, msg, strlen(S2M_INFORESPONSE_KPQ3)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
			return;
		server->isWaitResponce = qfalse;

		HandleInfoResponseKPQ3(server, msg + strlen(S2M_INFORESPONSE_KPQ3));
	}

// If it's a getservers request
//	else if (!strncmp(C2M_GETSERVERS_KPQ3, msg, strlen(C2M_GETSERVERS_KPQ3)))
//	{
//		HandleGetServersKPQ3(msg + strlen(C2M_GETSERVERS_KPQ3), address);
//	}

// If it's a getservers request.
	else if (!strncmp(C2M_GETSERVERS2_KPQ3, msg, strlen(C2M_GETSERVERS2_KPQ3)))
	{
		HandleGetServersKPQ3(msg + strlen(C2M_GETSERVERS2_KPQ3), address);
	}

// If it's a getmotd request
	else if (!strncmp(C2M_GETMOTD_KPQ3, msg, strlen(C2M_GETMOTD_KPQ3)))
	{
		HandleGetMotd(msg + strlen(C2M_GETMOTD_KPQ3), address);
	}

// If it's a shutdown request
	else if (!strncmp(S2M_FLATLINE_KPQ3, msg, strlen(S2M_FLATLINE_KPQ3))||
		!strncmp(S2M_FLATLINE2_KPQ3, msg, strlen(S2M_FLATLINE2_KPQ3)))
	{
		if (strstr(msg, "Flatline") != 0)
		{
			server = Sv_GetByAddr(address, qfalse);
			if (server == NULL)
				return;

			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s (%s) \n", peer_address, "'Flatline'", msg);
			server->timeout = crt_time /*+ TIMEOUT_CHALLENGE*/; //remove server
			server->isWaitResponce = qtrue;
		}
	}
// invalid
	else 
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s (%s)\n", peer_address,"invalid kpq3", msg);

}


/*
====================
HandleMessage
TCP
Parse a packet to figure out what to do with it
====================
*/
void HandleGspyMessage(const char *msg, const struct sockaddr_in *address, SOCKET_NET tmpSoc)
{
	char *value;
	const char *challenge = NULL;
	char *gamename;
	int tcp = 1;

// If it's gamespylite inital request
	if (!strncmp(B2M_INITALCONTACT, msg, strlen(B2M_INITALCONTACT)))
	{// \gamename\gspylite\gamever\01\location\0\validate\LO/WUC4c\final\\queryid\1.1\list\\gamename\kingpin

		gamename = strstr(msg, "\\list\\\\");
		if (gamename != NULL)
		{
			challenge = SearchInfostring((const char*)gamename, "gamename");
			if (challenge != NULL)
			{
				MsgPrint(MSG_DEBUG, "%-21s ---> %-22s GSLite (%s)\n", peer_address,"'\\list\\'", challenge);
				HandleGetServersGSpy(address, tcp, challenge, tmpSoc);
				return;
			}

		}

		MsgPrint(MSG_DEBUG, "%-21s ---> INVALID: gamename\n", peer_address);

	}
// old gamespy responce to request. //list//
	else if (!strncmp(B2M_GETSERVERS, msg, strlen(B2M_GETSERVERS))) 
	{ // \list\\gamename\kingpinver\01\location\0\validate\LO/WUC4c\final\\queryid\1.1

		/* Extract the game id */
		gamename = strstr(msg, "\\gamename");
		if (gamename != NULL)	{
			challenge = SearchInfostring((const char*)gamename, "gamename");
			if (challenge != NULL)
			{
				MsgPrint(MSG_DEBUG, "%-21s ---> %-22s GS B2M (%s)\n", peer_address, "'\\list\\'", challenge);
				HandleGetServersGSpy(address, tcp, challenge, tmpSoc);
				return;
			}
		}

		MsgPrint(MSG_DEBUG, "%-21s ---> INVALID: gamename\n", peer_address);

	}
//gslist server requests. //gamename//gamespy2//
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

		gamename = strstr(msg, "\\list\\");
		if (gamename != NULL)	{
			challenge = SearchInfostring((const char*)gamename, "gamename");
			if (challenge != NULL)
			{
				HandleGetServersGSpy(address, tcp, challenge, tmpSoc);
				MsgPrint(MSG_DEBUG, "%-21s ---> Sent GSList Packet \n", peer_address);
				return;
			}
		}

		MsgPrint(MSG_DEBUG, "%-21s ---> INVALID: gamename\n", peer_address);
	}
	else //error
	{
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s (%s)\n", peer_address, "INVALID: GameSpy", msg);
	}
}

/*
====================
IsInitialGameSpyPacket

packet is inital contact. echo back for more details
if it contains \list\ then we can use it
====================
*/
qboolean IsInitialGameSpyPacket(const char *msg)
{
	char *value;
	value = strstr(msg, "\\list\\");
	if (value != NULL)
		return 0;

	// If it's gamespylite request
	if (!strncmp(B2M_INITALCONTACT, msg, strlen(B2M_INITALCONTACT)) ||
		!strncmp(B2M_GETSERVERS_GSLIST2, msg, strlen(B2M_GETSERVERS_GSLIST2)))
		return qtrue;

	return qfalse;

}
