/*
	common.h

	Common header file for xrealmaster

	Copyright (C) 2004-2005  Mathieu Olivier

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


#ifndef _COMMON_H_
#define _COMMON_H_


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#ifdef WIN32
# include <winsock2.h>
//# include <vld.h>
#else
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <sys/socket.h>
#endif

//#define USE_ALT_OUTPORT


// ---------- Constants ---------- //

////////////////
//   global   //
////////////////

// Timeouts (in secondes)
#define TIMEOUT_HEARTBEAT		620 //kingpin default 300
#define TIMEOUT_INFORESPONSE	10	//seconds

// Period of validity for a challenge string (in secondes)
#define TIMEOUT_CHALLENGE 3

//hypov8 allow a bit of time for ping responce
#define TIMEOUT_PING 5

// Maximum size of a reponse packet
#define MAX_PACKET_SIZE 1400

//hypov8 block quake 2 etc
#define KINGPIN_ONLY

#define YYYY "\xFF\xFF\xFF\xFF" //ÿÿÿÿ

//max tcp clients
#define MAX_CLIENTS 8


////////////////
//  kp stuff  //
////////////////

// server to master
#define S2M_HEARTBEAT				"\\heartbeat\\"			//heartbeat GS packet
#define S2M_GAMENAME_KINGPIN		"\\gamename\\kingpin"	//gamename GS packet
#define S2M_FINAL					"\\final\\\\queryid\\"			//kingpin.exe responce to ack packet
#define S2M_HEARTBEAT_YYYY			YYYY"heartbeat\n"		//heartbeat game port
#define S2M_SHUTDOWN_YYYY			YYYY"shutdown"			//shutdown, server change, map etc
#define S2M_ACK_YYYY				YYYY"ack"				//recieved ack 
#define S2M_PING_YYYY				YYYY"ping"				//recieved ping (initilized server...)
#define S2M_PRINT_YYYY				YYYY"print\n"			//recieved print (after sending status...)
#define S2M_ERROR_STR				"Info string length exceeded\n" //fix strings to long. game port send limitation


// master to server
#define M2S_GETSTATUS_GS			"\\status\\"	//send status GS packet
#define M2S_GETSINFO_GS				"\\info\\"		//send info GS packet //todo? there should be a short server string
#define M2S_ACK_GS					"\\ack\\"		//reponde with an ack. Gamespy
#define M2S_GETSTATUS_YYYY			YYYY"status\n"	//send status game port
#define M2S_PING_YYYY				YYYY"ping\n"	//send ping, hoping to recieve ack
#define M2S_ACK_YYYY				YYYY"ack\n"		//reponde with an ack

//gamebrowser to master
#define B2M_GETSERVERS_LIST			"\\list\\"
#define B2M_GETSERVERS_QUERY		YYYY"query" //udp //hypov8 added YYYY. check other q2 browsers are ok still

//master to client. ingame browser
#define M2C_GETSERVERSREPONSE_Q2	YYYY"servers\n" // "servers (6 bytes)(6 bytes)" //hypov8 add \n todo check q2 browsers

//master to gamespy browser
#define M2B_KEY						"TXKOAT" //todo auto generate? //TXKOAT
#define M2B_ECHOREPLY				"\\basic\\\\secure\\" M2B_KEY //echo reply to gamespy "\\basic\\\\secure\\TXKOAT"

//client to master. ingame browser
#define C2M_GETMOTD					"getmotd" //hypov8 note YYYY or \\getmotd\\?

//master to client. ingame browser
#define M2C_MOTD					"motd "


////////////////
// kpq3 stuff //
////////////////

//server to master
#define S2M_HEARTBEAT_KPQ3			"heartbeat KingpinQ3-1" // "heartbeat Kingpinq3\n"
#define S2M_HEARTBEAT_DP			"heartbeat DarkPlaces"	// more accepted protocol name at other masters
#define S2M_INFORESPONSE_KPQ3		"infoResponse\x0A"		// "infoResponse\n\\pure\\1\\..."
#define S2M_FLATLINE_KPQ3			"KingpinQ3-1"			//kill kpq3 server
#define S2M_FLATLINE2_KPQ3			"DarkPlaces"			//kill kpq3 server

//master to server
#define M2S_GETINFO_KPQ3			YYYY"getinfo "				// "getinfo A_Challenge"
//#define M2S_GETSTATUS_KPQ3		"ÿÿÿÿgetstatus "

//client to master. ingame browser
#define C2M_GETSERVERS_KPQ3			"getservers KingpinQ3-1"	// "getservers KingpinQ3-1 75 empty full"
#define C2M_GETSERVERS2_KPQ3		"getservers "				// "getservers 68 empty full"	// not using darkplaces protocol
#define C2M_GETMOTD_KPQ3			"getmotd"

//master to client. ingame browser
#define M2C_GETSERVERSREPONSE_KPQ3	YYYY"getserversResponse\\" // "getserversResponse\\...(6 bytes)...\\...(6 bytes)...\\EOT\0\0\0"
#define M2C_CHALLENGE_KEY			"challenge\\"
#define M2C_MOTD_KEY				"motd\\"




// ---------- Types ---------- //
//gamespy
typedef unsigned char      uint8_t;
typedef uint8_t     u8;

typedef struct gamesList_s
{
	char*full_name;
	char*short_name;
	char*code_name;
}gamesList_t;



// A few basic types
typedef enum
{ 
	qfalse,
	qtrue 
} qboolean;

typedef unsigned char qbyte;

// The various messages levels
typedef enum
{
	MSG_NOPRINT,				// used by "max_msg_level" (= no printings)
	MSG_ERROR,					// errors
	MSG_WARNING,				// warnings
	MSG_NORMAL,					// standard messages
	MSG_DEBUG					// for debugging purpose
} msg_level_t;


// ---------- Public variables ---------- //

// The master socket
#ifdef WIN32
typedef SOCKET SOCKET_NET;
//#define SOCKET_NET SOCKET;
#else
typedef int SOCKET_NET;
#endif

extern SOCKET_NET		inSock_udp;
extern SOCKET_NET		inSock_kpq3; //listen on kpq3 port
#ifdef USE_ALT_OUTPORT
extern SOCKET_NET		outSock_udp;
extern SOCKET_NET		outSock_kpq3; // out kpq3
#endif
extern SOCKET_NET		inSock_tcp;

// The current time (updated every time we receive a packet)
extern time_t   crt_time;

// Maximum level for a message to be printed
extern msg_level_t max_msg_level;

// Peer address. We rebuild it every time we receive a new packet
extern char     peer_address[128];


// ---------- Public functions ---------- //

// Win32 uses a different name for some standard functions
#ifdef WIN32
# define snprintf		_snprintf
#define TCP_SHUTRECV	SD_RECEIVE
#define TCP_SHUTSEND	SD_SEND
#define TCP_SHUTBOTH	SD_BOTH
#define ERRORNUM		WSAGetLastError()
#define x_strdup		_strdup
#define x_strcmpi		_strcmpi
#else
#define TCP_SHUTRECV	SHUT_RD
#define TCP_SHUTSEND	SHUT_WR
#define TCP_SHUTBOTH	SHUT_RDWR
#define ERRORNUM		errno  //hypo ToDo: test
#define SOCKET_ERROR	-1
#define INVALID_SOCKET	-1
#define	x_strdup		strdup
#define x_strcmpi		strcasecmp
#endif

#ifndef max
#define max( x, y ) ( ( ( x ) > ( y ) ) ? ( x ) : ( y ) )
#define min( x, y ) ( ( ( x ) < ( y ) ) ? ( x ) : ( y ) )
#endif

// Print a message to screen, depending on its verbose level
int             MsgPrint(msg_level_t msg_level, const char *format, ...);


qboolean MAST_parseIPConversionFile(void);//add hypov8

//gamespy
int gslist_step_2(/*u8 *secure,*/ u8 *validate, char* browser, int enctype);

#endif							// _COMMON_H_
