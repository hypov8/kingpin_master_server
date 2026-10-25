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

//#define CURL_STATICLIB //defined in solution config
#ifdef WIN32
	#ifdef CURL_STATICLIB
		#include <curl/curl.h>
	#else
		#include <winhttp.h>
	#endif
#else
	#include <curl/curl.h>
	#include <pwd.h>
	#include <unistd.h>
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
	char      url[ADDRESS_LENGTHMAX];	// hypo dns
	qboolean  active;
	char      response[MAX_PACKET_SIZE_RECV];
	size_t    responseLen;
#if defined(WIN32) && !defined(CURL_STATICLIB)
	//win http
	HANDLE webThread;
	volatile int webDone;
#else
	//curl
	CURL  *webCurl;
#endif
} webList_t;
static webList_t webHostList[MAX_WEBLIST];


// ---------- Private variables ---------- //


//web list
//static int numwebList = 0;

static const char *webFileName_gamePort = "ip_weblist.txt";
static const char *webFileName_gameSpy  = "ip_weblist_gs.txt";

//last request type. use gamespy or Game protocol
static qboolean isWebGSPort = qtrue;


#if defined(WIN32) && !defined(CURL_STATICLIB)
//win http

#else
//curl
static CURLM *webMulti = NULL;
#endif

static int webActive = 0;

// ---------- Public variables ---------- //



// ---------- Private functions ---------- //


//todo move
qboolean isStringEOL(char c)
{
	if (isspace(c) || c == '\0' || c == '/')
		return qtrue;
	return qfalse;
}

qboolean isStringComment(char c)
{
	if (!c || c == '#' || c == '\\' || c == '/')
		return qtrue;
	return qfalse;
}


static qboolean WEB_ParseFile(qboolean isGSPorts)//char* webText
{
	int   len, count = 0;
	FILE *file = NULL;
	char *s, line[1024];

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
	
	while (fgets(line, 1024, file))
	{
		s = &line[0];

		// skip initial white space chars
		while (s[0] && isspace(s[0]))
			s++;

		// skip emtpy lines and comments
		if (isStringComment(s[0]))
			continue;

		// remove trailing white space chars
		len = strlen(s);
		while (len > 0 && isspace(s[len - 1]))
			s[--len] = 0;

		//nothing left to read
		if (!s[0])
			continue;

		//copy full url		
		strncpy(webHostList[count].url, s, ADDRESS_LENGTHMAX - 1);

		count++;
		if (count >= MAX_WEBLIST)
			break;
	}		

	fclose(file);

	return qtrue;
}


static qboolean WEB_parseWebListIPs(char *webText)
{
	int       i, numwebList = 0;
	int       portLen = 0;
	char     *tokenPtr;
	char      bufferIP[ADDRESS_LENGTHMAX], bufferPort[PORT_LENGTH];
	char     *saveptr;
	
	if (webText[0] == '\0')
		return 0;

	tokenPtr = strtok_r(webText, "\n", &saveptr); //new line token

	while (tokenPtr != NULL)
	{
		// skip initial white space chars
		while (*tokenPtr && isspace(*tokenPtr))
			tokenPtr++;

		// skip blank lines and comments
		if (isStringComment(*tokenPtr)){
			tokenPtr = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		// trim leading whitespace (but keep the rest of the line)
		while (isspace((unsigned char)*tokenPtr)){
			tokenPtr++;
		}

		// Skip whitespace. or not a number
		if (!*tokenPtr || *tokenPtr < '0' || *tokenPtr > '9'){
			tokenPtr = strtok_r(NULL, "\n", &saveptr); //read next token/line
			continue;
		}

		portLen = 0;
		bufferIP[0] = '\0';
		bufferPort[0] = '\0';

		//port = qfalse;
		for (i = 0; i < ADDRESS_LENGTHMAX; i++)
		{
			if (isStringEOL(*tokenPtr))
				break;

			//port
			if (*tokenPtr == ':')
			{
				tokenPtr++;
				for (; portLen < PORT_LENGTH; portLen++)
				{
					if (isStringEOL(*tokenPtr))
						break;
					bufferPort[portLen] = *tokenPtr;
					tokenPtr++;
				}
				break;
			}
			bufferIP[i] = *tokenPtr;
			tokenPtr++;
		}
		//null terminate
		bufferIP[i] = '\0';
		bufferPort[portLen] = '\0';

		if (!CFG_AddServerToList(numwebList, bufferIP, bufferPort))
			break;

		numwebList += 1;
		tokenPtr = strtok_r(NULL, "\n", &saveptr);
	}

	return numwebList;
}


void WEB_ProcessWebRecData(int index)
{
	int numwebList;
	webList_t *host;

	host = &webHostList[index];
	

	if (host->response[0] == '\0')
		//todo error...
		return;

	numwebList = WEB_parseWebListIPs(host->response); //return new realoc ptr

	if (numwebList)
		CFG_PingServerList(numwebList, isWebGSPort);
	else
		// Error, couldn't parse web reply.
		MsgPrint(MSG_WARNING, "WEBLIST: Invalid server list recieved \n");
}




#if defined(WIN32) && !defined(CURL_STATICLIB)
//win http
DWORD WINAPI WEB_WinHttp_FetchThread(LPVOID arg)
{
	int i = *(int*)arg;
	// blocking WinHTTP calls here - fine, it's a background thread
	// WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
	// WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData...
	webDone[i] = 1;
	return 0;
}

void WEB_SendQueryToWebHost_WinHttp(webList_t *list)
{
	
	webList_t *host;

	for (int i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (list[i].address[0] == '\0') 
			continue;
		webDone[i] = 0;
		webResponseLen[i] = 0;
		host->webThread = CreateThread(NULL, 0, webFetchThread, &i, 0, NULL);
	}
}

void WEB_PollWinHttp(void)
{
	
	webList_t *host;

	for (int i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (host->webThread && webDone[i])   // <- just reading an int, instant
		{
			// response is ready
			CloseHandle(host->webThread);
			host->webThread = NULL;
		}
	}
}
#else //curl

static size_t WEB_WriteCallback(char *data, size_t size, size_t nmemb, void *userptr)
{
	size_t total = size * nmemb;
	webList_t *host = (webList_t *)userptr;
	size_t offset = host->responseLen;

	if (offset + total >= MAX_PACKET_SIZE_RECV -1)
		return 0;  // signal curl to abort (buffer full)

	memcpy(host->response + offset, data, total);
	host->responseLen += total;
	host->response[host->responseLen] = '\0';
	return total;
}


static void WEB_SendQueryToWebHost_Curl()
{
	int i;
	char userAgent[128];
	CURL  *curl;
	webList_t *host;

	sprintf(userAgent, "KingpinMaster/%s", KP_MASTER_VERSION);

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (host->url[0] == '\0')
			continue;

		host->webCurl = curl_easy_init();
		if (!host->webCurl)
			continue;

		curl = host->webCurl;

		// build URL: http://host:port/file

		curl_easy_setopt(curl, CURLOPT_URL, host->url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WEB_WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, host);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // required for multi on Windows
		curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent);
		curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 300);
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

		//debug
		//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);   

		host->active = qtrue;
		host->responseLen = 0;
		host->response[0] = 0;
		curl_multi_add_handle(webMulti, curl);
		webActive++;
	}
}


//run every 100ms. when master is inactive
static void WEB_PollCurl(void)
{
	int still_running = 0;
	int msgs_left;
	int i;
	CURLMsg *msg;
	webList_t *host;

	if (webActive == 0)
		return;

	// non-blocking: makes progress on all active transfers, returns immediately
	curl_multi_perform(webMulti, &still_running);

	// empty queue
	while ((msg = curl_multi_info_read(webMulti, &msgs_left)) != NULL)
	{
		if (msg->msg != CURLMSG_DONE)
			continue;

		//find matching server
		for (i = 0; i < MAX_WEBLIST; i++)
		{
			host = &webHostList[i];
			if (host->webCurl != msg->easy_handle)
				continue;

			if (msg->data.result != CURLE_OK)
			{
				MsgPrint(MSG_WARNING, "WEBLIST: %s failed: %s\n",
					host->url, curl_easy_strerror(msg->data.result));

				// only print if something actually came through
				if (host->responseLen > 0)
					MsgPrint(MSG_DEBUG, "WEBLIST: partial: [%s]\n", host->response);
			}
			else
			{
				MsgPrint(MSG_DEBUG, "WEBLIST: got %d bytes from %s\n",
					(int)host->responseLen, host->url);

				// dump the actual response
				MsgPrint(MSG_DEBUG|MSG_COL_2, "WEBLIST: [%s]\n", host->response);

				//read the ip lists
				WEB_ProcessWebRecData(i);
			}

			curl_multi_remove_handle(webMulti, host->webCurl);
			curl_easy_cleanup(host->webCurl);
			host->webCurl = NULL;
			host->active = qfalse;
			webActive--;
			break;  // found match
		}

		//debug
		if (i == MAX_WEBLIST)
			MsgPrint(MSG_ERROR, "WEBLIST: orphan handle in multi queue\n");
	}
}


static void WEB_CleanupWebList()
{
	int i;
	webList_t *host;

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];

		if (host->webCurl)
		{
			curl_multi_remove_handle(webMulti, host->webCurl);
			curl_easy_cleanup(host->webCurl);
			host->webCurl = NULL;
#if _DEBUG
			MsgPrint(MSG_WARNING, "WEBLIST: curl index %i was not free\n", i + 1);
#else
			MsgPrint(MSG_DEBUG, "WEBLIST: curl index %i was not free\n", i + 1);
#endif
		}
		host->url[0] = 0;
		host->response[0] = 0;
		host->responseLen = 0;
		host->active = qfalse;
	}
	webActive = 0;
}


static void WEB_SendQueryToWebHost()
{
#if defined(WIN32) && !defined(CURL_STATICLIB)
	WEB_SendQueryToWebHost_WinHttp();
#else
	WEB_SendQueryToWebHost_Curl();
#endif

}

#endif


// ---------- Public functions ---------- //

void WEB_PollWebList(void)
{
#if defined(WIN32) && !defined(CURL_STATICLIB)
	WEB_PollWinHttp();
#else
	WEB_PollCurl();
#endif
}

/*
====================
WEB_Begin_Send

Load WebList
====================
*/
//static void CONFIG_ReadWebList(qboolean isGS)
void WEB_Begin_Send()
{
	Sv_MemCheck("web1_begin");

	isWebGSPort = !isWebGSPort; //switch between GS and Gameport

	WEB_CleanupWebList();

	//open weblist.txt. if valid, send packet
	if (WEB_ParseFile(isWebGSPort))
	{
		Sv_MemCheck("web2_parsed");
		WEB_SendQueryToWebHost();
	}

	Sv_MemCheck("web3_end");
}


void WEB_Init_Curl()
{
#if !defined(WIN32) || defined(CURL_STATICLIB)
	curl_global_init(CURL_GLOBAL_ALL);
	webMulti = curl_multi_init();
#endif
}

void WEB_Init()
{
#if !defined(WIN32) || defined(CURL_STATICLIB)
	WEB_Init_Curl();
#endif
}


void WEB_Cleanup_Curl() 
{
	int i;
	webList_t *host;

	// clean up any remaining handles first
	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (host->webCurl)
		{
			curl_multi_remove_handle(webMulti, host->webCurl);
			curl_easy_cleanup(host->webCurl);
			host->webCurl = NULL;
		}
	}

	curl_multi_cleanup(webMulti);
	curl_global_cleanup();
}

void WEB_Cleanup()
{
#if !defined(WIN32) || defined(CURL_STATICLIB)
	WEB_Cleanup_Curl();
#endif
}
