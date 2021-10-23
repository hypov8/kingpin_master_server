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
MSG_SearchInfostring

Search an infostring for the value of a key
====================
*/
static char *MSG_SearchInfostring(const char *infostring, const char *key)
{
	static char		value[256];
	char			crt_key[256];
	size_t			value_ind, key_ind;
	char			c;

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
MSG_BuildChallenge_KPQ3

Build a challenge string for a "getinfo" message
====================
*/
static const char *MSG_BuildChallenge_KPQ3(void)
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
MSG_SendGetStatus_GSPort

Send a //status// message to a kp server on udp Gamespy port
====================
*/
static void MSG_SendGetStatus_GSPort(const struct sockaddr_in *ServerAddress, SOCKET_NET recv_sock)
{
	char	tmpIP[128];

	//gs port
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_udp, M2S_GETSTATUS_GS, strlen(M2S_GETSTATUS_GS), 0,
		(const struct sockaddr *)ServerAddress, sizeof(*ServerAddress)) >= 0)
#else
	if (sendto(recv_sock, M2S_GETSTATUS_GS, strlen(M2S_GETSTATUS_GS), 0,
		(const struct sockaddr *)ServerAddress, sizeof(*ServerAddress)) >= 0)
#endif
	{	//send ok
		snprintf(tmpIP, sizeof(tmpIP), "%s:%hu", 
			inet_ntoa(ServerAddress->sin_addr), ntohs(ServerAddress->sin_port));
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (GameSpy Port) \n",
			tmpIP, "\'\\\\status\\\\\'");
	}
	else
	{	//send error
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s --== Socket Error ==-- \"%i\"\n",
			peer_address, "\'\\\\status\\\\\'", ERRORNUM);
	}
}

/*
====================
MSG_SendGetStatus_GPort

Send a "status" message on game port
inital cointact. get protocol etc..
====================
*/
static void MSG_SendGetStatus_GPort(server_t * server, SOCKET_NET recv_sock)
{
	char	msg[64] = M2S_GETSTATUS_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);

#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_udp, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#else
	if (sendto(recv_sock, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#endif
	{	//send ok
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (Game Port) \n",
			peer_address, "\'YYYYstatus\'");
	}
	else
	{	//send error
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n",
			peer_address, "\'YYYYstatus\'", ERRORNUM);
	}
}


/*
====================
MSG_SendGetInfo_KPQ3

Send a "getinfo" message to a KPQ3 server
====================
*/
static void MSG_SendGetInfo_KPQ3(server_t * server, SOCKET_NET recv_sock)
{
	char msg[64] = M2S_GETINFO_KPQ3;//"\xFF\xFF\xFF\xFF" M2S_GETINFO_KPQ3 " ";

	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		strncpy(server->challenge, MSG_BuildChallenge_KPQ3(), sizeof(server->challenge));
		server->challenge_timeout = crt_time + TIMEOUT_CHALLENGE;
	}

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
	strncat(msg, "\n", sizeof(msg) - strlen(msg) - 1);

#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_kpq3, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#else
	if (sendto(recv_sock, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#endif
	{	//sent ok
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s challenge (%s) \n",
			peer_address, "\'getinfo\'", server->challenge);
	}
	else
	{	//send error
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s (error: %i) \n",
			peer_address, "WARNING: cant send \'getinfo\'", ERRORNUM);
	}
}


/*
====================
MSG_SendPing_GPort

kingpin
====================
*/
static void MSG_SendPing_GPort(server_t * server, SOCKET_NET recv_sock)
{
	char msg[64] = M2S_PING_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);
#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_udp, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#else
	if (sendto(recv_sock, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#endif
	{	//send ok
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (Game Port) \n",
			peer_address, "\'YYYYPing\'");
	}
	else
	{	//send error
		MsgPrint(MSG_WARNING, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n",
			peer_address, "\'YYYYPing\'", ERRORNUM);
	}
}


/*
====================
MSG_SendAck_GPort

kingpin on Game UDP port
====================
*/
static void MSG_SendAck_GPort(server_t * server, SOCKET_NET recv_sock)
{
	char msg[64] = M2S_ACK_YYYY;

	strncat(msg, server->challenge, sizeof(msg) - strlen(msg) - 1);

#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_udp, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#else
	if (sendto(recv_sock, msg, strlen(msg), 0,
		(struct sockaddr *)&server->address, sizeof(server->address)) >= 0)
#endif
	{	//send ok
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (Game Port) \n",
			peer_address, "\'YYYYAck\'");
	}
	else
	{	//send error
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n",
			peer_address, "\'YYYYAck\'", ERRORNUM);
	}
}


/*
====================
MSG_SendAck_GSPort

kingpin on GameSpy UDP port
====================
*/
static void MSG_SendAck_GSPort(server_t * server, SOCKET_NET recv_sock)
{
	struct sockaddr_in tmpServerAddress;

	memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
	memcpy(&tmpServerAddress, &server->address, sizeof(tmpServerAddress));
	tmpServerAddress.sin_port = htons(server->gsPort);

#ifdef USE_ALT_OUTPORT
	if (sendto(outSock_udp, M2S_ACK_GS, strlen(M2S_ACK_GS), 0,
		(struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)) >= 0)
#else
	if (sendto(recv_sock, M2S_ACK_GS, strlen(M2S_ACK_GS), 0,
		(struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)) >= 0)
#endif
	{	//send ok
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Sent (GameSpy Port)\n",
			peer_address, "\'\\\\Ack\\\\\'");
	}
	else
	{	//send error
		MsgPrint(MSG_DEBUG, "%-21s <--- %-22s --== Socket Error ==-- (%i) \n",
			peer_address, "\'\\\\Ack\\\\\'", ERRORNUM);
	}

}


/*
====================
MSG_fixStringToLongError_GPort

kingpin sends "Info string length exceeded\n"
for game port 
this offsets pointer so \\xx\\yy\\ can be parsed
====================
*/
static int MSG_fixStringToLongError_GPort(const char* msg, int nb_bytes)
{
	int offset = 0;
	//char *ptr = (char*)msg;
	//int sLen = strlen(S2M_ERROR_STR);

	while (msg[offset] != '\\' && offset < nb_bytes)
	{
		offset++;
		//ptr += sLen;
	}

	return offset;
}

/*
====================
MSG_RespondToGetServers_GSpyTCP

Parse getservers requests and send the appropriate response
TCP
====================
*/
static void MSG_RespondToGetServers_GSpyTCP(const struct sockaddr_in *addr, int gsEncType,
											const char* challenge, SOCKET_NET clientTCPSoc)
{
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind=0;
	server_t       *sv;
	unsigned long    sv_addr;
	unsigned short  sv_port;
	char			*print_sv_addr;
	char			printStr[MAX_PACKET_SIZE*2];
	char			tmp_packet[30];
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
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s (%s) \n", peer_address, "\'getservers\'", challenge);


	// Initialize the packet contents with the header
	memset(packet, 0, sizeof(packet)); //reset packet, prevent any issues
	memset(printStr, 0, sizeof(printStr));

	// Add every relevant server
	for (sv = Sv_GetFirst(); /* see below */; sv = Sv_GetNext())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof(packet) - (7 + 6))
		{
			// End Of Transmission
			if ( sv == NULL ) {
				packet[ packetind + 0 ] = '\\';
				packet[ packetind + 1 ] = 'f';
				packet[ packetind + 2 ] = 'i';
				packet[ packetind + 3 ] = 'n';
				packet[ packetind + 4 ] = 'a';
				packet[ packetind + 5 ] = 'l';
				packet[ packetind + 6 ] = '\\';
				packetind += 7;
			}

			// Send the packet to the client
			sendto(clientTCPSoc, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
				
			if (max_msg_level <= MSG_NORMAL)  //hypov8 print if no debug 
			{
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "%s (%s)", "getservers", challenge );
				if (gsEncType >= 0) //glist
					MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %u (GL)\n", peer_address, tmp, numServers);
				else
					MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %u (GS)\n", peer_address, tmp, numServers);
			}

			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s (Gamespy) (%u servers)\n", 
				peer_address, "getservers Response", numServers);

			MsgPrint(MSG_DEBUG, "%s\n%s \n%s \n",	
				"=================================================",
				printStr,  //hypov8 todo PrintPacket()
				"=================================================");

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = 0;
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


		print_sv_addr = inet_ntoa(sv->address.sin_addr);

		sv_addr = ntohl(sv->address.sin_addr.s_addr);
		if (isKingpin)
			sv_port = sv->gsPort; //-10 send gamespy query port to clients (gslist/gspylite)
		else
			sv_port = ntohs(sv->address.sin_port);

		// Use the address mapping associated with the server, if any
		if (sv->addressReMap != NULL)
		{
			const addrmap_t *addrmap = sv->addressReMap;
			print_sv_addr = inet_ntoa(addrmap->to.sin_addr);

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


		if (gsEncType >= 0) //gslist. send as byte
		{
			// IP address
			packet[packetind + 0] = sv_addr >> 24;
			packet[packetind + 1] = (sv_addr >> 16) & 0xFF;
			packet[packetind + 2] = (sv_addr >> 8) & 0xFF;
			packet[packetind + 3] = sv_addr & 0xFF;

			// Port
			packet[packetind + 4] = sv_port >> 8;
			packet[packetind + 5] = sv_port & 0xFF;
			packetind += 6;
			// add server to printed debug packet
			sprintf(printStr, "%s/ip/%s:%hu", printStr, print_sv_addr, sv_port);
		}
		else //gsEncType -1 (gspylite)
		{
			sprintf(tmp_packet, "\\ip\\%s:%i", print_sv_addr, sv_port);
			strcat(packet, tmp_packet);
			packetind += strlen(tmp_packet);
			// add server to printed debug packet
			sprintf(printStr, "%s/ip/%s:%hu", printStr, print_sv_addr, sv_port);
		}
		numServers++;
	}
}


/*
====================
MSG_RespondToGetServers_Quake

q2 protocol
====================
*/
static void MSG_RespondToGetServers_Quake(const struct sockaddr_in *addr, SOCKET_NET recv_sock)
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
		MsgPrint(MSG_NORMAL, "%-21s ---> getservers (QuakeBrowser) \n", peer_address);

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
			// none on quake2?

			MsgPrint(MSG_DEBUG, "- Sending packet: servers %s\n", print);

#ifdef USE_ALT_OUTPORT
			sendto(outSock_udp, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
#else
			sendto(recv_sock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
#endif
			if ( max_msg_level <= MSG_NORMAL ) { //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %u (GB)\n",
					peer_address, "getservers (quake)", numServers);
			}
			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s Quake (%u servers)\n",
				peer_address, "getservers Response", numServers);


			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		sv_port = ntohs(sv->address.sin_port);
		sv_addr = ntohl(sv->address.sin_addr.s_addr);
		// Use the address mapping associated with the server, if any
		if (sv->addressReMap != NULL)		
		{
			const addrmap_t *addrmap = sv->addressReMap;

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


/*
====================
MSG_RespondToGetServers_KPQ3

Parse getservers requests and send the appropriate response
====================
*/
static void MSG_RespondToGetServers_KPQ3(const char *msg, const struct sockaddr_in *addr, SOCKET_NET recv_sock)
{
	const char     *packetheader = M2C_GETSERVERSREPONSE_KPQ3; //"\xFF\xFF\xFF\xFF" M2C_GETSERVERSREPONSE_KPQ3 "\\";
	const size_t    headersize = strlen(packetheader);
	char			gamename[64] = "";
	char            packet[MAX_PACKET_SIZE];
	size_t          packetind;
	server_t       *sv;
	unsigned int    protocol;
	char			*print_sv_addr; //add hypov8
	char			printStr[MAX_PACKET_SIZE*2];	//add hypo
	unsigned long   sv_addr;
	unsigned short  sv_port;
	qboolean        no_empty;
	qboolean        no_full;
	unsigned int    numServers = 0;


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


	if ( max_msg_level >= MSG_DEBUG ) { //hypov8 print b4 debug stuff below
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s kingpinQ3 (P:%d) \n",
			peer_address, "\'getservers\'", protocol);
	}

	// must exist to show all servers
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
			if ( sv == NULL ){
				packet[ packetind + 0 ] = 'E';
				packet[ packetind + 1 ] = 'O';
				packet[ packetind + 2 ] = 'T';
				packet[ packetind + 3 ] = '\0';
				packet[ packetind + 4 ] = '\0';
				packet[ packetind + 5 ] = '\0';
				packetind += 6;
			}

			// Send the packet to the client
#ifdef USE_ALT_OUTPORT
			sendto(outSock_kpq3, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(struct sockaddr));
#else
			sendto(recv_sock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(struct sockaddr));
#endif			
			if ( max_msg_level <= MSG_NORMAL ) { //hypov8 print if no debug 
				MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Servers: %i (GB)(P:%d)\n",
					peer_address, "getservers (kingpinQ3)", numServers, protocol);
			}
			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s KingpinQ3 (%u servers)\n",
				peer_address, "getservers Response", numServers);
			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s (packet:\' %s \') \n\n",
				peer_address,"Sending servers", packet);
			MsgPrint(MSG_DEBUG, "%-21s <--- %-22s (packet:\' %s \') \n\n",
				peer_address,"Sending servers", printStr);

			// If we're done
			if (sv == NULL)
				return;

			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		print_sv_addr = inet_ntoa(sv->address.sin_addr);
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
		if (sv->addressReMap != NULL)
		{
			const addrmap_t *addrmap = sv->addressReMap;
			print_sv_addr = inet_ntoa(sv->address.sin_addr);

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

		sprintf(printStr, "%s/ip/%s:%hu", printStr, print_sv_addr, sv_port);
#endif
		packetind += 7;
		numServers++;
	}

}


/*
====================
MSG_HandleInfoResponse_KPQ3

Parse infoResponse messages
====================
*/
static void MSG_HandleInfoResponse_KPQ3(server_t * server, const char *msg)
{
	char           *value;
	unsigned int    protocol = 0;
	unsigned short  maxclients = 0;

	MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'infoResponse\'");

	// Check the challenge
	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		MsgPrint(MSG_WARNING, "%-21s ---> %-22s Obsolete challenge \n",
			peer_address, "WARNING: \'infoResponse\'");
		return;
	}
	value = MSG_SearchInfostring(msg, "challenge");
	if (!value || strcmp(value, server->challenge))
	{
		MsgPrint(MSG_WARNING, "%-21s ---> %-22s Challenge SV(%s) M(%s) \n",
			peer_address, "WARNING: \'infoResponse\'", value, server->challenge);
		return;
	}

	// Check and save the values of "protocol" and "maxclients"
	value = MSG_SearchInfostring(msg, "protocol");
	if (value)
		protocol = atoi(value);
	value = MSG_SearchInfostring(msg, "sv_maxclients");
	if (value)
		maxclients = (unsigned short)atoi(value);
	if (!protocol || !maxclients)
	{
		MsgPrint(MSG_WARNING,"%-21s ---> %-22s Invalid (protocol: %d, maxclients: %d) \n",
			peer_address, "WARNING: \'infoResponse\'", protocol, maxclients);
		return;
	}
	server->protocol = protocol;
	server->maxclients = maxclients;

	// Save some other useful values
	value = MSG_SearchInfostring(msg, "clients");
	if (value)
		server->nbclients = (unsigned short)atoi(value);

	value = MSG_SearchInfostring(msg, "gamename");
	if (value == NULL)
	{
		value = S2M_FLATLINE_KPQ3;	// Q3A doesn't send a gamename, so we add it manually
		MsgPrint(MSG_WARNING, "%-21s ---> %-22s Invalid gamename\n",
			peer_address, "WARNING: \'infoResponse\'");
	}

	// If the gamename has changed
	if (x_strcmpi(server->gamename, value))
	{
		if (x_strcmpi(server->gamename ,""))
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Changed (%s to %s) \n",
				peer_address, "Server gamename", server->gamename, value);

		strncpy(server->gamename, value, sizeof(server->gamename) - 1);
	}

	// Set a new timeout
	server->timeout = crt_time + TIMEOUT_HEARTBEAT;
}


/*
====================
MSG_RespondToGetMotd_KPQ3

Parse getservers requests and send the appropriate response
hypov8 todo: hows does this work.. text file?
====================
*/
static void MSG_RespondToGetMotd_KPQ3(const char *msg, const struct sockaddr_in *addr, SOCKET_NET recv_sock)
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

	value = MSG_SearchInfostring(msg, "challenge");
	if(!value)
	{
		MsgPrint(MSG_ERROR, "%-21s ---> ERROR: invalid challenge (%s) \n", peer_address, value);
		return;
	}

	strncpy(challenge, value, sizeof(challenge) - 1);
	challenge[sizeof(challenge) - 1] = '\0';

	value = MSG_SearchInfostring(msg, "renderer");
	if(value)
	{
		strncpy(renderer, value, sizeof(renderer) - 1);
		renderer[sizeof(renderer) - 1] = '\0';
		MsgPrint(MSG_DEBUG, "%-21s ---> is using renderer %s\n", peer_address, value);
	}

	value = MSG_SearchInfostring(msg, "version");
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
	sendto(recv_sock, packet, packetind, 0, (const struct sockaddr *)addr, sizeof(*addr));
}

// ---------- Public functions ---------- //

/*
====================
MSG_HandleMessage_KP1

kingpin
Parse a packet to figure out what to do with it
====================
*/
void MSG_HandleMessage_KP1(const char *msg, const struct sockaddr_in *address, SOCKET_NET recv_sock, int nb_bytes)
{
	server_t			*server;
	char				*value;
	struct sockaddr_in	tmpServerAddress;

////////////////
//Gamespy packet

//GS.. \\heartbeat\\31500\\gamename\\kingpin.
	if(!strncmp(S2M_HEARTBEAT, msg, strlen(S2M_HEARTBEAT)))
	{
		// Extract the game id
		value = MSG_SearchInfostring(msg, "gamename");
		if (value == NULL)	{
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No GameName \n",
				peer_address, "\'\\Heartbeat\\\'");
			return;		
		}
#ifdef KINGPIN_ONLY
		if (!(x_strcmpi(value, "kingpin") == 0)) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Not Kingpin (%s) \n",
				peer_address, "\'\\heartbeat\\\'", value);
			return;		
		}
#endif
		value = MSG_SearchInfostring(msg, "heartbeat"); //port
		if (value == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No port \n",
				peer_address, "\'\\HeartBeat\\\'");
			return;		
		}

		/* copy to tmp. dont store server */
		memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
		memcpy(&tmpServerAddress, address, sizeof(tmpServerAddress));

		/* send //status// on port found in string. initial contact is random port */
		/* it looks like this is used to make sure gamespy port is open (no firewall) */
		tmpServerAddress.sin_port = htons((u_short)atoi(value));

		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\\\'Heartbeat\\\'");

		/* get more info before storing server */
		MSG_SendGetStatus_GSPort((const struct sockaddr_in*)&tmpServerAddress, recv_sock); //status//
	}

//GS.. //gamename//kingpin//.
	else if (!strncmp(S2M_GAMENAME_KINGPIN, msg, strlen(S2M_GAMENAME_KINGPIN)))
	{
		int protocol;

		// Extract the game id
		value = MSG_SearchInfostring(msg, "protocol");
		if (value == NULL) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No protocol \n", 
				peer_address, "\'gamename\\\\kingpin\'");
			return;
		}
		protocol = atoi(value);

#ifdef KINGPIN_ONLY
		if (protocol !=  32) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Not Kingpin protocol (%i) \n", 
				peer_address, "\'gamename\\\\kingpin\'", protocol);
			return;
		}
#endif	
		// Extract "private"
		value = MSG_SearchInfostring(msg, "private");
		if (value && atoi(value)==1){
			MsgPrint(MSG_NORMAL, "%-21s ---> IS PRIVATE \n", peer_address);
			return;
		}

		// Extract hostport
		value = MSG_SearchInfostring(msg, "hostport");
		if (value == NULL) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No hostport \n", 
				peer_address, "\'gamename\\\\kingpin\'");
			return;
		}

		memset(&tmpServerAddress, 0, sizeof(tmpServerAddress));
		memcpy(&tmpServerAddress, address, sizeof(tmpServerAddress));
		tmpServerAddress.sin_port = htons((u_short)atoi(value));

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr((const struct sockaddr_in*)&tmpServerAddress, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server \n", 
				peer_address, "\'gamename\\\\kingpin\'");
			return;
		}

		server->gsPort = ntohs(address->sin_port); //gamespy port. recieve port
		server->active = qtrue;
		server->protocol = protocol;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s Saved (GameSpy port) \n", 
			peer_address, "\'gamename\\\\kingpin\'");
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;

		//hypo reply to server. acknowledge packet recieved
		MSG_SendAck_GSPort(server, recv_sock); //ToDo: check gs? 
	}

//GS.. //final////queryid//. Responce to ack  
	else if (!strncmp(S2M_FINAL, msg, strlen(S2M_FINAL)))
	{
		//do nothing
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s kingpin.exe\n",
			peer_address, "\'final\\\\queryid\'");
	}
//
//end Gamespy packets
//////////////////////


/////////////////////
//game port packet

//GP.. yyyyHeartbeat\n. Server active. Reply ACK
	else if (!strncmp(S2M_HEARTBEAT_YYYY, msg, strlen(S2M_HEARTBEAT_YYYY)))
	{
		int protocol;
		int hbLen = strlen(S2M_HEARTBEAT_YYYY);
		int offset = MSG_fixStringToLongError_GPort(msg+hbLen, nb_bytes);

		// Extract "private"
		value = MSG_SearchInfostring(msg +hbLen+offset, "private");
		if (value && atoi(value) == 1){
			MsgPrint(MSG_NORMAL, "%-21s ---> IS PRIVATE \n", peer_address);
			return;
		}

		// Extract the game id
		value = MSG_SearchInfostring(msg +hbLen+offset, "protocol");
		if (value == NULL)		{
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No protocol found (using kingpin 32) \n", peer_address, "\'YYYYHeartbeat\'");
			protocol = 32;
		}
		else
			protocol = atoi(value);

#ifdef KINGPIN_ONLY
		if (protocol !=  32)	{ //force kingpin only servers (no quake2)
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Protocol not 32\n", peer_address, "\'YYYYHeartbeat\'");
			return;
		}
#endif	
		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "\'YYYYHeartbeat\'");
			return;	
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port )- (u_short)10 ;

		server->active = qtrue;
		server->protocol = protocol;
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'YYYYHeartbeat\'");

		//hypo reply to server. acknowledge packet recieved
#if 0 
		MSG_SendAck_GPort(server, recv_sock);
#else
		//debug force an "info string length exceeded\n"
		MSG_SendGetStatus_GPort(server, recv_sock); 
#endif
	}

//GP.. yyyyprint\n. Recieve a full info packet
	else if ((!strncmp(S2M_PRINT_YYYY, msg, strlen(S2M_PRINT_YYYY))))
	{
		int protocol;
		int hbLen = strlen(S2M_PRINT_YYYY);
		int offset = MSG_fixStringToLongError_GPort(msg+hbLen, nb_bytes);

		// Extract "private"
		value = MSG_SearchInfostring(msg+hbLen+offset, "private");
		if (value && atoi(value) == 1){
			MsgPrint(MSG_NORMAL, "%-21s ---> IS PRIVATE \n", peer_address);
			return;
		}

		// Extract the game id
		value = MSG_SearchInfostring(msg+hbLen+offset, "protocol");
		if (value == NULL) {
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s No protocol \n", peer_address, "\'YYYYprint\'");
			return;	
		}
		protocol = atoi(value);

#ifdef KINGPIN_ONLY
		if (protocol !=  32)	{
			MsgPrint(MSG_NORMAL, "%-21s ---> %-22s Protocol not 32 (kingpin) \n", peer_address, "\'YYYYprint\'");
			return;	
		}
#endif
		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr(address, qtrue);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server \n", peer_address, "\'YYYYprint\'");
			return;		
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

		server->active = qtrue;
		server->protocol = protocol;
		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'YYYYprint\'");

		//hypo reply to server. acknowledge packet recieved
		MSG_SendAck_GPort(server, recv_sock);
	}

//GP.. YYYYshutdow. Check if status changed or quit
	else if (!strncmp(S2M_SHUTDOWN_YYYY, msg, strlen(S2M_SHUTDOWN_YYYY)))
	{
		/* check for a valid server */
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
		{	//hypov8 server did not send initial heartbeat. add it
			server = Sv_GetByAddr(address, qtrue);
			if (server == NULL) {
				MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "\'YYYYShutdown\'");
				return;
			}
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			server->isWaitResponce = qtrue;
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s add server\n", peer_address, "\'YYYYShutdown\'");
			MSG_SendGetStatus_GPort(server, recv_sock);
			return;
		}

		server->timeout = crt_time + TIMEOUT_PING;
		server->isWaitResponce = qtrue;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'YYYYShutdown\'");

		/* check if server is active or shutdown */
		MSG_SendPing_GPort(server, recv_sock);
	}
//GP.. YYYYack. Server sent ack. keep active. do we need to check if status changed?
	else if (!strncmp(S2M_ACK_YYYY, msg, strlen(S2M_ACK_YYYY)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL) {
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "\'YYYYAck\'");
			return;		
		}

		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
	}
//GP.. YYYYping. Server sent ping. Respons with ACK
	else if (!strncmp(S2M_PING_YYYY, msg, strlen(S2M_PING_YYYY)))
	{
		/* check for a valid server */
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL) 
		{	//hypov8 server didnt send initial heartbeat. add it
			server = Sv_GetByAddr(address, qtrue);
			if (server == NULL)
			{
				MsgPrint(MSG_DEBUG, "%-21s ---> %-22s No Server\n", peer_address, "\'YYYYPing\'");
				return;	
			}

			//hypo have to assume gamespy port.
			if (!server->gsPort)
				server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			server->isWaitResponce = qtrue;
			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s New Server \n", peer_address, "\'YYYYPing\'");
			MSG_SendGetStatus_GPort(server, recv_sock);
			return;
		}

		//hypo have to assume gamespy port.
		if (!server->gsPort)
			server->gsPort = ntohs(server->address.sin_port) - (u_short)10;

		server->timeout = crt_time + TIMEOUT_HEARTBEAT;
		server->isWaitResponce = qfalse;
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'YYYYPing\'");

		if (!server->protocol){
			server->timeout = crt_time + TIMEOUT_INFORESPONSE;
			server->isWaitResponce = qtrue;
			MSG_SendGetStatus_GPort(server, recv_sock);
		}
		else
			MSG_SendAck_GPort(server, recv_sock);
	}
//GP.. YYYYgetmotd. client to master. getmotd request. ToDo: motd
	else if(!strncmp(C2M_GETMOTD, msg, strlen(C2M_GETMOTD)))
	{
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s kp1\n", peer_address, "\'getmoto\'");
		//hypov8 todo:
		//MSG_RespondToGetMotd_KP1(msg + strlen(C2M_GETMOTD), address, recv_sock);
	}
//GP.. YYYYquery. Quake2 master query.	
	else if (!strncmp(B2M_GETSERVERS_QUERY_YYYY, msg, strlen(B2M_GETSERVERS_QUERY_YYYY)))
	{
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s Request quake server packet \n", peer_address, "\'YYYYquery..\'");
		MSG_RespondToGetServers_Quake(address, recv_sock);
	}
//GP.. query. Quake2 master query.	
	else if (!strncmp(B2M_GETSERVERS_QUERY, msg, strlen(B2M_GETSERVERS_QUERY)))
	{
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s Request quake server packet \n", peer_address, "\'query..\'");
		MSG_RespondToGetServers_Quake(address, recv_sock);
	}
//error
	else
	{
		MsgPrint(MSG_NORMAL, "%-21s ---> Invalid packet!!!     (%s) \n", peer_address, msg);
	}
}


/*
====================
MSG_HandleMessage_KPQ3

kingpinq3
Parse a packet to figure out what to do with it
====================
*/
void MSG_HandleMessage_KPQ3(const char *msg, const struct sockaddr_in *address, SOCKET_NET recv_sock)
{
	server_t       *server;

// If it's an heartbeat
	if (!strncmp(S2M_HEARTBEAT_DP, msg, strlen(S2M_HEARTBEAT_DP)))
	{
		char            gameId[64];

		// Extract the game id
		sscanf(msg + strlen(S2M_HEARTBEAT_DP) + 1, "%63s", gameId);
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'heartbeat Darkplaces\'"/*, gameId*/);

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
		MSG_SendGetInfo_KPQ3(server, recv_sock);
	}

// If it's an heartbeat (old name kpq3)
	else if (!strncmp(S2M_HEARTBEAT_KPQ3, msg, strlen(S2M_HEARTBEAT_KPQ3)))
	{
		char            gameId[64];

		// Extract the game id
		sscanf(msg + strlen(S2M_HEARTBEAT_KPQ3) + 1, "%63s", gameId);
		MsgPrint(MSG_DEBUG, "%-21s ---> %-22s \n", peer_address, "\'heartbeat KingpinQ3-1\'"/*, gameId*/);

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
		MSG_SendGetInfo_KPQ3(server, recv_sock);
	}

// If it's an infoResponse message
	else if (!strncmp(S2M_INFORESPONSE_KPQ3, msg, strlen(S2M_INFORESPONSE_KPQ3)))
	{
		server = Sv_GetByAddr(address, qfalse);
		if (server == NULL)
			return;
		server->isWaitResponce = qfalse;

		MSG_HandleInfoResponse_KPQ3(server, msg + strlen(S2M_INFORESPONSE_KPQ3));
	}

// If it's a getservers request
//	else if (!strncmp(C2M_GETSERVERS_KPQ3, msg, strlen(C2M_GETSERVERS_KPQ3)))
//	{
//		HandleGetServersKPQ3(msg + strlen(C2M_GETSERVERS_KPQ3), address);
//	}

// If it's a getservers request.
	else if (!strncmp(C2M_GETSERVERS2_KPQ3, msg, strlen(C2M_GETSERVERS2_KPQ3)))
	{
		MSG_RespondToGetServers_KPQ3(msg + strlen(C2M_GETSERVERS2_KPQ3), address, recv_sock);
	}

// If it's a getmotd request
	else if (!strncmp(C2M_GETMOTD_KPQ3, msg, strlen(C2M_GETMOTD_KPQ3)))
	{
		MSG_RespondToGetMotd_KPQ3(msg + strlen(C2M_GETMOTD_KPQ3), address, recv_sock);
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

			MsgPrint(MSG_DEBUG, "%-21s ---> %-22s (%s) \n", peer_address, "\'Flatline\'", msg);
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
MSG_HandleMessage_GspyTCP
TCP
Parse a packet to figure out what to do with it


gspylite
\gamename\gspylite\gamever\01\location\0\validate\LO/WUC4c\final\\queryid\1.1\list\\gamename\kingpin

( gslist.exe -n kingpin -Y gspylite mgNUaC -x 192.168.2.123:28900 -t 0 )
\gamename\gspylite\enctype\0\validate\LO/WUC4c\final\\list\cmp\gamename\kingpin

( gslist.exe -n kingpin -Y kigpin QFWxY2 -x 192.168.2.123:28900 -t 0 )
\gamename\kigpin\enctype\0\validate\wwke+FSs\final\\list\cmp\gamename\kingpin

( gslist.exe -n kingpin -x 192.168.2.123:28900 -t 0 )
\gamename\gamespy2\gamever\20603020\enctype\0\validate\UpkV3Mfn\final\\list\cmp\gamename\kingpin

( gslist.exe -n kingpin -x 192.168.2.123:28900 -t -1 )
\&\\\\\kingpin\gslive\w^)Hk=f%\\\\\

====================
*/
int MSG_HandleMessage_GspyTCP(const char *msg, const struct sockaddr_in *address, int clientID)
{
	const char *value; // , *list = "\\list\\";
	char  challenge_list[64];
	char str_pt1[1024], *str_pt2;
	int out=0;
	size_t len1 = 0, len2 = 0;
	qboolean str_list = qfalse;
	u8 	validate[89];

	if (clientinfo_tcp[clientID].timeout > crt_time && clientinfo_tcp[clientID].socknum != INVALID_SOCKET) //client valid?
	{
		//check for  "\\list\\". split string
		str_pt2 = strstr(msg, B2M_GETSERVERS_LIST);
		if (str_pt2 != NULL) 
		{
			len2 = strlen(str_pt2);
			if (len2 > 0) {
				value = MSG_SearchInfostring((const char*)str_pt2, "gamename");
				if (value != NULL)	{
					strcpy(challenge_list, value);
					str_list = qtrue;
				}
			}
		}

		//check if packet is the inital responce with client id and validation.
		len1 = strlen(msg);
		if ((len1 - len2) > 1 )	
		{
			//split string
			strcpy(str_pt1, msg);
			str_pt1[len1 - len2] = '\0';

			//browser type
			value = MSG_SearchInfostring((const char*)str_pt1, "gamename");//decrypt
			if (value != NULL)
				strcpy(clientinfo_tcp[clientID].browser_type, value);

			//encrypted key responce
			value = MSG_SearchInfostring((const char*)str_pt1, "validate");//decrypt
			if (value != NULL)
				strcpy(clientinfo_tcp[clientID].decrypt_str, value);

			//gslist sends enc type
			value = MSG_SearchInfostring(str_pt1, "enctype");
			if ( value != NULL )
				clientinfo_tcp[ clientID ].gsEncType = atoi(value);

			//validate browser and encryption
			if (clientinfo_tcp[clientID].browser_type[0] && clientinfo_tcp[clientID].decrypt_str[0])
			{
				out = gslist_step_2(validate, clientinfo_tcp[clientID].browser_type, clientinfo_tcp[ clientID ].gsEncType);

				if (out && (strcmp(clientinfo_tcp[clientID].decrypt_str, (char*)validate)) == 0)
					clientinfo_tcp[clientID].valid = qtrue;
			}
		}

		//valid client, get next packet or wait for next packet
		if (clientinfo_tcp[clientID].valid)
		{
			if (str_list)
			{
				MsgPrint(MSG_DEBUG, "%-21s ---> %-22s GSLite (%s)\n", peer_address, B2M_GETSERVERS_LIST, challenge_list);
				//send responce
				MSG_RespondToGetServers_GSpyTCP(address, clientinfo_tcp[ clientID ].gsEncType,
					challenge_list, clientinfo_tcp[clientID].socknum);
				return 1; //close connection
			}
			else
				return 0; //dont dissconnect valid client. wait for list
		}
	}
	else
	{
		MsgPrint(MSG_NORMAL, "%-21s ---> %-22s (%s)\n", peer_address, "ERROR: Client Timeout", msg);
		return 1; //kill connection
	}

	//failed client
	MsgPrint(MSG_NORMAL, "%-21s ---> %-22s (%s)\n", peer_address, "INVALID: GameSpy", msg);
	return 1; //kill connection
}
