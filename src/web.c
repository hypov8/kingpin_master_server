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

/*
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>
#include <curl/curl.h>
//CURL_STATICLIB;
//.\include;
*/

#ifndef WIN32
# include <pwd.h>
# include <unistd.h>
#endif

#include "common.h"
#include "messages.h"
#include "servers.h"


// ---------- Constants ---------- //






// ---------- Types ---------- //

#ifdef WIN32
//typedef int socklen_t;
#endif

typedef struct
{
	char      address[ADDRESS_LENGTHMAX];	// hypo dns
	char      port[PORT_LENGTH];
	char      file[ADDRESS_LENGTHMAX];
	qboolean  isHttps;
} webList_t;


// ---------- Private variables ---------- //

//web list
static int numwebList = 0;

static const char *webFileName_gamePort = "ip_weblist.txt";
static const char *webFileName_gameSpy  = "ip_weblist_gs.txt";

//last request type. use gamespy or Game protocol
static qboolean isWebGSPort = qtrue;


// ---------- Public variables ---------- //

extern SOCKET_NET    webSock_tcp[MAX_WEBLIST];
//extern ipPortList_t *serverListsToPing;


// ---------- Private functions ---------- //


static qboolean WEB_ParseFile(qboolean isGSPorts, webList_t *webHostList)//char* webText
{
	int   len, count = 0;
	FILE *file = NULL;
	char *s, line[1024];
	char *tmpIP, *tmpPort, *tmpFile;
	webList_t *host;

	if ( isGSPorts ) {
		MsgPrint(MSG_DEBUG, "Loading... %s\n", webFileName_gameSpy);
		file = fopen(webFileName_gameSpy, "r");
	}
	else {
		MsgPrint(MSG_DEBUG, "Loading... %s\n", webFileName_gamePort);
		file = fopen(webFileName_gamePort, "r");
	}

	if(!file)
		return qfalse;
	
	while (fgets(line, 1024, file) && count < MAX_WEBLIST)
	{
		s = &line[0];

		// skip initial white space chars
		while (s[0] && isspace(s[0]))
			s++;

		// skip emtpy lines and comments
		if (s[0] == '\0' || s[0] == '#' || !strncmp(s, "//", 2))
			continue;

		// remove trailing white space chars
		len = strlen(s);
		while (len > 0 && isspace(s[len - 1]))
			s[--len] = 0;

		//nothing left to read
		if (!s[0])
			continue;

		host = &webHostList[count];
		strcpy(host->port, "80");
		//begin with http?
		if (x_strnicmp(s, "http://", 7) == 0)
		{
			host->isHttps = qfalse;
			s += 7;
		}
		else if (x_strnicmp(s, "https://", 8) == 0)
		{
			host->isHttps = qtrue;
			strcpy(host->port, "443");
			s += 8;
		}
		tmpIP = s;

		//has a port?
		tmpPort = strstr(s, ":");
		if (tmpPort != NULL)
		{
			tmpPort[0] = '\0';
			tmpPort++;
			s = tmpPort;
		}

		//has a file path
		tmpFile = strstr(s, "/");
		if (!tmpFile)
			continue;

		tmpFile[0] = '\0';
		tmpFile++;

		if (tmpPort)
			strcpy(host->port, tmpPort);
		strcpy(host->address, tmpIP);
		sprintf(host->file, "/%s", tmpFile);
		count++;
	}		

	fclose(file);

	return qtrue;
}


static qboolean WEB_parseWebListIPs(char *webText)
{
	int       i, k, numwebList = 0;
	int       portLen = 0;
	char     *tokenPtr;
	char      c, bufferIP[ADDRESS_LENGTHMAX], bufferPort[PORT_LENGTH];
	qboolean  port;
	//ipPortList_t *list;
	
	if (!webText[0])
		return 0;

	tokenPtr = strtok(webText, "\n"); //new line token
	
	//skip header text
	if (strstr(tokenPtr, "HTTP/") != NULL)
	{
		char ok1[20], ok2[20];
		int result = sscanf(tokenPtr, "%s %s", ok1, ok2 ); //HTTP/1.1 200 OK
		if (result && ok2[0] != '2')
			return 0; //failed

		while (tokenPtr != NULL)
		{
			tokenPtr = strtok(NULL, "\n");
			//find \n\r\n or \n\n
			if (tokenPtr == NULL || isspace(tokenPtr[0])) 
				break;
		}
	}

	while (tokenPtr != NULL)
	{
		k = 0;
		c = tokenPtr[0];

		// Skip whitespace
		if (!c || isspace(c) || c == '\\'||c == '/')
		{
			tokenPtr = strtok(NULL, "\n"); //read next token/line
			continue;
		}

		//start's with a number?
		if (c < '0' || c > '9')
		{
			tokenPtr = strtok(NULL, "\n"); //read next token/line
			continue;
		}

		port = qfalse;
		for (i = 0; i < ADDRESS_LENGTHMAX; i++)
		{
			c = tokenPtr[i];
			if (isspace(c))	
				break;

			//end of line
			if (isspace(c) || c == '\0')
				break;

			//port
			if (c == ':')
			{
				port = qtrue;
				for (portLen = 0; portLen < PORT_LENGTH; portLen++)
				{
					c = tokenPtr[i + portLen + 1];
					if (isspace(c) || c == '\0')
						break;
					bufferPort[portLen] = c;
				}
				break;
			}
			bufferIP[i] = c;
		}
		//null terminate
		bufferIP[i] = '\0';
		bufferPort[portLen] = '\0';

		if (!CFG_AddServerToList(numwebList, bufferIP, bufferPort))
			break;

		numwebList += 1;
		tokenPtr = strtok(NULL, "\n");
	}

	return numwebList;
}





static void WEB_SendQueeryToWebHost(webList_t *webHostList)
{
	int                 i;
	struct sockaddr_in  tmpServerAddress;
	char                message[MAX_PACKET_SIZE_RECV];
	const char         *webFileName;
	webList_t          *host;

	if (isWebGSPort) {
		MsgPrint(MSG_DEBUG, "Processing WebList: Gamespy\n");
		webFileName = webFileName_gameSpy;
	}
	else {
		MsgPrint(MSG_DEBUG, "Processing WebList: Gameport\n");
		webFileName = webFileName_gamePort;
	}

	//loop through max web list. send inital contact
	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (host->address[0] != '\0')
		{
			//validate address
			Sv_MemCheck("websendQ1");
			if (!Sv_ResolveAddr(host->address, &tmpServerAddress))
			{
			Sv_MemCheck("websendQ2");
				continue;
			}
			Sv_MemCheck("websendQ3");
			//use port
			tmpServerAddress.sin_port = htons((u_short)atoi(host->port));

			webSock_tcp[i] = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //hypov8
			if (webSock_tcp[i] == INVALID_SOCKET)	{
				MsgPrint(MSG_WARNING, "WARNING: Socket() failed for weblist (error: %d)\n", ERRORNUM);
				SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
				continue;
			}

			if (connect(webSock_tcp[i], (struct sockaddr *)&tmpServerAddress, sizeof(tmpServerAddress)) == SOCKET_ERROR){
				MsgPrint(MSG_WARNING, "WARNING: Connect() failed. ( %s index: %i error: %d ) \n",
					webFileName, i + 1, ERRORNUM);
				SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
				continue;
			}

			sprintf(message,
				"GET %s HTTP/1.1\r\n" // GET /list.htm HTTP/1.1
				"Host: %s:%s\r\n"   // Host: www.123.com
				"User-Agent: KingpinMaster/%s\r\n"
				"Accept: text/html\r\n"
				"Content-Type: text/html\r\n"
				"\r\n",
				host->file,
				host->address, host->port, //ip:port
				KP_MASTER_VERSION);

			MsgPrint(MSG_DEBUG, 
				"WEBLIST: Sending:\n"
				"=================================================\n");
			MsgPrint(MSG_DEBUG | MSG_COL_2, "%s", message);
			MsgPrint(MSG_DEBUG, "=================================================\n");

			//ioctlsocket(webSock_tcp[i], FIONBIO, &iMode);
			//Send some data
			if (send(webSock_tcp[i], message, strlen(message), 0) == SOCKET_ERROR)
			{
				MsgPrint(MSG_WARNING, 
					"WARNING: Send() failed. ( %s index: %i error: %d ) \n",
					webFileName, i + 1, ERRORNUM);
				SocketError_close(webSock_tcp[i], SOCKET_WEB, i);
				continue;
			}

			MsgPrint(MSG_DEBUG, "WEBLIST: \'send\' completed ok. ( %s address: %i )\n", webFileName, i + 1);
		}
	}
}


// ---------- Public functions ---------- //


/*
====================
WEB_HandleResponce

respopnce from WebList
====================
*/
//void MAST_WebList_Responce(int recieveSock)
void WEB_HandleResponce(int recvSockIdx) 
{
	int  i, iResult;
	char recvbuf[MAX_PACKET_SIZE_RECV+1];
	char recvbufAll[MAX_PACKET_SIZE_RECV * 3+1];
	int  numwebList = 0; 

	//memset(&recvbufAll, 0, sizeof(recvbufAll));
	recvbufAll[0] = 0;

	//hypo todo: will sit here waiting for next packet.. 100+ servers set global?
	for (i = 0; i < 3; i++) //3 gets then timeout
	{
		iResult = recv(webSock_tcp[recvSockIdx], recvbuf, MAX_PACKET_SIZE_RECV, 0);
		if (iResult > 0)
		{
			if (strlen(recvbufAll) + iResult < MAX_PACKET_SIZE_RECV*3) {
				strncat(recvbufAll, recvbuf, iResult);
				MsgPrint(MSG_DEBUG, "WEBLIST: Bytes received: %d\n", iResult);
			}
			else {
				MsgPrint(MSG_WARNING, "WARNING: Buffer full\n");
				break;
			}
		}
		else if (iResult == SOCKET_ERROR)
		{
			MsgPrint(MSG_WARNING, "WARNING: WEBLIST \'recv\' Failed. (Error: %d)\n", ERRORNUM);
			break;
		}
		else //iResult = 0
		{
			MsgPrint(MSG_DEBUG, "WEBLIST: Packet empty\n");
			break; //empty...
		}

		//check header text
		if (!x_strnicmp(recvbufAll, "HTTP/", 5))
		{	//HTTP/1.1 301 Moved Permanently..
			//HTTP/1.1 400 Bad Request..
			char s1[20], s2[20], s3[200];
			int result = sscanf(recvbufAll, "%s %s %s", s1, s2, s3); //HTTP/1.1 200 OK
			if (result && s2[0] != '2')
			{
				MsgPrint(MSG_WARNING, "ERROR: Getting WebList \'%s %s %s\'\n", s1, s2, s3);
				break; //failed
			}
		}

		//if packed was not full then it must be done
		if (iResult > 0 && iResult < MAX_PACKET_SIZE_RECV){
			MsgPrint(MSG_DEBUG, "WEBLIST: Finished. Bytes received: %i\n", iResult);
			break;
		}
	}

	// shutdown the connection since no more data will be sent
	if (shutdown(webSock_tcp[recvSockIdx], TCP_SHUTBOTH) == SOCKET_ERROR)
		MsgPrint(MSG_WARNING, "WARNING: WEBLIST \'shutdown\' Failed. (Error: %d)\n", ERRORNUM);
	SocketError_close(webSock_tcp[recvSockIdx], SOCKET_WEB, recvSockIdx);

	if (!recvbufAll[0])
		return;

	numwebList = WEB_parseWebListIPs(recvbufAll); //return new realoc ptr
	if (numwebList)
		CFG_PingServerList(numwebList, isWebGSPort);
	else
		// Error, couldn't parse web reply.
		MsgPrint(MSG_WARNING, "WEBLIST: Invalid server list recieved \n");

}

void WEB_CloseSockets()
{
	int i;

	//reset sockets
	for(i = 0; i < MAX_WEBLIST; i++)
	{
		//did not disconect properly
		if ( webSock_tcp[ i ] != INVALID_SOCKET )
		{
			if (shutdown(webSock_tcp[i], TCP_SHUTBOTH) == SOCKET_ERROR)
				MsgPrint(MSG_WARNING, "WARNING: WEBLIST \'shutdown\' Failed. (Error: %d)\n", ERRORNUM);
			SocketError_close(webSock_tcp[ i ], SOCKET_WEB, i);
		}
	}
}

/*
====================
WEB_Begin

Load WebList
====================
*/
//static void CONFIG_ReadWebList(qboolean isGS)
void WEB_Begin()
{
	webList_t webHostList[MAX_WEBLIST];

	Sv_MemCheck("web1_begin");

	WEB_CloseSockets();
	memset(&webHostList, 0, sizeof(webHostList));
	isWebGSPort = !isWebGSPort; //switch between GS and Gameport

	//open weblist.txt. if valid, send packet
	if (WEB_ParseFile(isWebGSPort, &webHostList[0]))
	{
		Sv_MemCheck("web2_parsed");
		WEB_SendQueeryToWebHost(&webHostList[0]);
	}

	Sv_MemCheck("web3_end");
}


void  WEB_Init()
{
#if 0
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl) 
	{
		//curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
		//curl_easy_setopt(curl, CURLOPT_URL, "http://kingpin.hambloch.com/servers_active.php?gameport=0");

		curl_easy_setopt(curl, CURLOPT_URL, "https://www.quakeservers.net/lists/australia/au-sv.txt");

#ifdef SKIP_PEER_VERIFICATION
		/*
		 * If you want to connect to a site who is not using a certificate that is
		 * signed by one of the certs in the CA bundle you have, you can skip the
		 * verification of the server's certificate. This makes the connection
		 * A LOT LESS SECURE.
		 *
		 * If you have a CA cert for the server stored someplace else than in the
		 * default bundle, then the CURLOPT_CAPATH option might come handy for
		 * you.
		 */
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
		/*
		 * If the site you are connecting to uses a different host name that what
		 * they have mentioned in their server certificate's commonName (or
		 * subjectAltName) fields, libcurl refuses to connect. You can skip this
		 * check, but it makes the connection insecure.
		 */
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

		/* cache the CA cert bundle in memory for a week */
		curl_easy_setopt(curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L);

		/* Perform the request, res gets the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));

		/* always cleanup */
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();
#endif
}
