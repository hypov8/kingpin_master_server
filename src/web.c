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


#include "common.h"
#include "messages.h"
#include "servers.h"

//#define CURL_STATICLIB //defined in solution config
#ifdef WIN32
	#include <winhttp.h> //fallback in curl missing
#else
	#include <curl/curl.h>
	#include <pwd.h>
	#include <unistd.h>
#endif


#include "web_curl.h"
static HMODULE g_hCurl = NULL;
static qboolean useCurl = qfalse;


// ---------- Constants ---------- //




// ---------- Types ---------- //

#ifdef WIN32
//typedef int socklen_t;
#endif

typedef struct
{
	char      url[ADDRESS_LENGTHMAX];	// ip/dns
	qboolean  active;
	char      response[MAX_PACKET_SIZE_RECV];
	size_t    responseLen;
#if defined(WIN32)
	//win http
	HANDLE       webWake;   // event: "work available"
	int          redirectCount;
	volatile int webDone;
	volatile DWORD webError;
	HINTERNET hRequest;   // per-host request handle
	HINTERNET hConnect;
#endif
	//curl
	CURL  *webCurl;
} webList_t;
static webList_t webHostList[MAX_WEBLIST];


// ---------- Private variables ---------- //


//web list
//static int numwebList = 0;

static const char *webFileName_gamePort = "ip_weblist.txt";
static const char *webFileName_gameSpy  = "ip_weblist_gs.txt";

//last request type. use gamespy or Game protocol
static qboolean isWebGSPort = qfalse; //this will get gamespy lists first


#if defined(WIN32)
//win http
static HINTERNET hGlobalSession = NULL; 
#endif

//curl
static CURLM *webMulti = NULL;


static int webActive = 0;

// ---------- Public variables ---------- //



// ---------- Private functions ---------- //

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
		if (Com_isStringComment(s[0]))
			continue;

		// remove trailing white space chars
		len = strlen(s);
		while (len > 0 && isspace(s[len - 1]))
			s[--len] = 0;

		//nothing left to read
		if (!s[0])
			continue;

		if (x_strnicmp(s, "http", 4) != 0)
			snprintf(webHostList[count].url, ADDRESS_LENGTHMAX - 1, "http://%s", s);
		else
			strncpy(webHostList[count].url, s, ADDRESS_LENGTHMAX - 1);

		count++;
		if (count >= MAX_WEBLIST)
			break;
	}		

	fclose(file);

	return qtrue;
}


static qboolean WEB_parseWebListIPs(char *webText, qboolean isGSPort)
{
	int   numwebList = 0;
	char *tokenPtr;
	char  bufferIP[ADDRESS_LENGTHMAX], bufferPort[PORT_LENGTH];
	char *saveptr, *lineStart;
	
	if (webText[0] == '\0')
		return 0;

	tokenPtr = strtok_r(webText, "\n", &saveptr); //new line token

	while (tokenPtr != NULL)
	{
		// skip initial white space chars
		lineStart = tokenPtr;
		while (*lineStart && isspace((unsigned char)*lineStart))
			lineStart++;

		//get adderess, handle invalid chars
		if (!Com_GetIpPortFromLine(lineStart, bufferIP, bufferPort))
		{
			tokenPtr = strtok_r(NULL, "\n", &saveptr);
			continue;
		}
		
		// Ensure row isn't blank before committing to configuration file
		if (bufferIP[0] != '\0')
		{
			if (!CFG_AddServerToList(numwebList, bufferIP, bufferPort, isGSPort))
				break;
			numwebList += 1;
		}

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
	{	
		//todo error...
		return;
	}

	numwebList = WEB_parseWebListIPs(host->response, isWebGSPort); //return new realoc ptr

	if (numwebList)
	{
		CFG_PingServerList(numwebList, isWebGSPort, LIST_WEB);
	}
	else
		// Error, couldn't parse web reply.
		MsgPrint(MSG_WARNING, "WEBLIST: Invalid server list recieved \n");
}


#if defined(WIN32)
//win http

static qboolean WEB_SendQueryToWebHost_WinHttp_Single(webList_t *host, int listIndex)
{
	wchar_t szHost[256] = { 0 };  // Cleanly initialized
	wchar_t wpath[1024] = { 0 };
	wchar_t wUrl[ADDRESS_LENGTHMAX] = { 0 };
	HINTERNET hConnect = NULL, hRequest = NULL;
	URL_COMPONENTS uc = { 0 };

	host->webDone = 0;
	host->webError = 0;
	host->responseLen = 0;

	MultiByteToWideChar(CP_UTF8, 0, host->url, -1, wUrl, ADDRESS_LENGTHMAX);

	uc.dwStructSize = sizeof(uc);
	uc.dwHostNameLength = (DWORD)-1;
	uc.dwUrlPathLength = (DWORD)-1;
	uc.dwExtraInfoLength = (DWORD)-1;
	uc.dwSchemeLength = (DWORD)-1;

	if (!WinHttpCrackUrl(wUrl, 0, 0, &uc))
	{
		host->webError = GetLastError();
		MsgPrint(MSG_WARNING, "CrackUrl: Error:%ul url: %s\n",host->webError, host->url);
		host->webDone = 0;
		return qfalse;
	}

	// Safely copy the host name up to its precise length
	if (uc.dwHostNameLength >= 256) 
		uc.dwHostNameLength = 255;
	wcsncpy_s(szHost, 256, uc.lpszHostName, uc.dwHostNameLength);
	szHost[uc.dwHostNameLength] = L'\0'; // Explicit terminate

	// Safely copy path + query parameters
	DWORD pathLen = uc.dwUrlPathLength + uc.dwExtraInfoLength;
	if (pathLen >= 1024) 
		pathLen = 1023;
	wcsncpy_s(wpath, 1024, uc.lpszUrlPath, pathLen);
	wpath[pathLen] = L'\0';

	// Handle standard port defaults if cracking returned 0
	INTERNET_PORT port = uc.nPort;
	if (port == 0) {
		port = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
	}
#if 0
	wcsncpy_s(szHost, 1024, uc.lpszHostName, uc.dwHostNameLength);
	wcsncpy_s(wpath, 1024, uc.lpszUrlPath, uc.dwUrlPathLength + uc.dwExtraInfoLength);
	szHost[uc.dwHostNameLength] = L'\0';
	wpath[uc.dwUrlPathLength + uc.dwExtraInfoLength] = L'\0';
#endif

	// 1. Establish connection and check for errors immediately!
	hConnect = WinHttpConnect(hGlobalSession, szHost, uc.nPort, 0);
	if (!hConnect)
	{
		MsgPrint(MSG_WARNING, "Connect: Error:%ul url: %s\n",host->webError, host->url);
		host->webError = GetLastError();
		return qfalse;
	}
	// 2. Open request safely using the validated hConnect
	hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath,
		NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
		(uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
	if (!hRequest)
	{
		host->webError = GetLastError();
		MsgPrint(MSG_WARNING, "OpenRequest: Error:%ul url: %s\n",host->webError, host->url);
		WinHttpCloseHandle(hConnect);
		return qfalse;
	}

	// --- ASYNC TIMEOUT CONFIGURATIONS ---
	// Parameters: Resolve, Connect, Send, Receive (in milliseconds)
	WinHttpSetTimeouts(hRequest, 5000, 5000, 5000, 10000);

	// Optimisation: Disable keep-alive and cookies. 
	// REMOVED WINHTTP_DISABLE_REDIRECTS so your custom callback handler receives them!
	DWORD off = WINHTTP_DISABLE_KEEP_ALIVE | WINHTTP_DISABLE_COOKIES;
	WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &off, sizeof(off));

	// Optimisation: Don't scan local client certificate stores on every async loop
	WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
					 WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);

	// --- IGNORE SSL CERTIFICATE ERRORS ---
	DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        | // Untrusted Root CAs
	                SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  | // Invalid usages
	                SECURITY_FLAG_IGNORE_CERT_CN_INVALID   | // Domain mismatch (e.g. accessing by IP)
	                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;  // Expired certificates
	WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));


	// Map handles to permanent structure before triggering async execution
	host->hConnect = hConnect;
	host->hRequest = hRequest; 

	// Trigger the request asynchronously
	if (!WinHttpSendRequest(host->hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0, 0,
		(DWORD_PTR)listIndex))
	{
		host->webError = GetLastError();
		if (host->hRequest) 
			WinHttpCloseHandle(host->hRequest);
		if (host->hConnect) 
			WinHttpCloseHandle(host->hConnect);
		host->hRequest = NULL;
		host->hConnect = NULL;
		//host->webDone = 1;
		MsgPrint(MSG_WARNING, "SendRequest: Error:%ul url: %s\n",host->webError, host->url);
		return qfalse;
	}

	return qtrue;
}

static void WEB_SendQueryToWebHost_WinHttp(void)
{
	webList_t *host;
	int i;

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];

		if (host->url[0] == '\0')
			continue;

		if (!WEB_SendQueryToWebHost_WinHttp_Single(host, i))
			continue;

		webActive++;
	}
}

static void CALLBACK WEB_Callback_WinHttp(
	HINTERNET hInternet,
	DWORD_PTR dwContext,
	DWORD dwInternetStatus,
	LPVOID lpvStatusInformation,
	DWORD dwStatusInformationLength)
{
	int curIdx = (int)dwContext; 
	webList_t *host;

	if (curIdx < 0 || curIdx >= MAX_WEBLIST)
		return;

	host = &webHostList[curIdx];

	switch (dwInternetStatus)
	{
		case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
			// Send finished. Safely tell the background pool to start reading headers.
			WinHttpReceiveResponse(hInternet, NULL);
			break;

		case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
			{
				// Check HTTP status code
				DWORD statusCode = 0, statusCodeSize = sizeof(statusCode);
				WinHttpQueryHeaders(hInternet,
					WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
					WINHTTP_HEADER_NAME_BY_INDEX,
					&statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

				if (statusCode >= 400)
				{
					host->webError = statusCode;
					host->webDone = 1; // TERMINAL FAILURE
					break;
				}
				else if (statusCode >= 300)
				{
					// Redirect
					wchar_t wLocation[1024] = { 0 };
					DWORD locLen = sizeof(wLocation) / sizeof(wchar_t);

					if (WinHttpQueryHeaders(hInternet, WINHTTP_QUERY_LOCATION,
							WINHTTP_HEADER_NAME_BY_INDEX,
							wLocation, &locLen, WINHTTP_NO_HEADER_INDEX))
					{
						WideCharToMultiByte(CP_UTF8, 0, wLocation, -1, host->url, sizeof(host->url), NULL, NULL);
					}

					host->webError = statusCode; 
					host->webDone = 1; // TERMINAL REDIRECT (Handled by poll)
					break;
				}

				// Headers OK. Kick off the data payload query
				host->responseLen = 0;
				WinHttpQueryDataAvailable(hInternet, NULL);
			}
			break;

		case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
			{
				DWORD dwSize = *(DWORD*)lpvStatusInformation;

				if (dwSize == 0)
				{
					// Clean EOF reached. The request is fully complete!
					host->webDone = 1; // TERMINAL SUCCESS
				}
				else
				{
					// Guard against buffer overflow
					if (host->responseLen + dwSize >= MAX_PACKET_SIZE_RECV)
					{
						dwSize = (MAX_PACKET_SIZE_RECV - host->responseLen) - 1;
					}

					if (dwSize <= 0)
					{
						host->response[host->responseLen] = '\0';
						host->webDone = 1; // TERMINAL BUFFER FULL
						break;
					}

					// Request data to be poured directly into your array slice
					WinHttpReadData(hInternet, &host->response[host->responseLen], dwSize, NULL);
				}
			}
			break;

		case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
			{
				DWORD dwBytesRead = dwStatusInformationLength;

				if (dwBytesRead > 0)
				{
					host->responseLen += dwBytesRead;
					host->response[host->responseLen] = '\0'; // Enforce null terminator

					// Loop back around to read the next chunk of data
					WinHttpQueryDataAvailable(hInternet, NULL);
				}
				else
				{
					// End of stream reached cleanly
					host->webDone = 1; // TERMINAL SUCCESS
				}
			}
			break;

		case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
			{
				// If an async operation actually fails, WinHTTP lands here.
				WINHTTP_ASYNC_RESULT* pResult = (WINHTTP_ASYNC_RESULT*)lpvStatusInformation;
				
				// Make sure we ignore the non-error code
				if (pResult->dwError != ERROR_IO_PENDING)
				{
					host->webError = pResult->dwError;
					host->webDone = 1; // TERMINAL FAILURE
				}
			}
			break;

		default:
			break;
	}
}

static void WEB_ResetWebList_WinHttp_Single(webList_t *host, qboolean full);
void WEB_PollWinHttp(void)
{
	int i;
	webList_t *host;

	if (webActive <= 0) 
	{
		webActive = 0;
		return;
	}

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (!host->webDone)
			continue;

		host->webDone = 0;
		webActive--;

		// Check if it was an HTTP error code or a Windows API error code
		if (host->webError == 301 || host->webError == 302 || host->webError == 307|| host->webError == 308)
		{
			host->redirectCount++;
			if (host->redirectCount < 5 && host->url[0] != '\0')
			{
				WEB_ResetWebList_WinHttp_Single(host, qfalse);
				if (WEB_SendQueryToWebHost_WinHttp_Single(host, i))
				{
					webActive++;
				}
			}
			MsgPrint(MSG_DEBUG, "WEBLIST: Network redirect id:%lu  to:%s\n", host->webError, host->url);
		}
		else if (host->webError != 0)
		{
			MsgPrint(MSG_WARNING, "WEBLIST: error %lu from %s\n", host->webError, host->url);
			WEB_ResetWebList_WinHttp_Single(host, qfalse);
		}
		else if (host->responseLen > 0)
		{
			WEB_ProcessWebRecData(i);
			WEB_ResetWebList_WinHttp_Single(host, qfalse);
		}
		else
		{
			MsgPrint(MSG_WARNING, "WEBLIST: Empty response from %s\n", host->url);
			WEB_ResetWebList_WinHttp_Single(host, qfalse);
		}
	}
}

static void WEB_ResetWebList_WinHttp_Single(webList_t *host, qboolean full)
{
	HINTERNET hTempRequest = host->hRequest;
	HINTERNET hTempConnect = host->hConnect;

	if (full) {
		host->redirectCount = 0;
		host->url[0] = '\0';
	}
	
	host->hRequest = NULL;
	host->hConnect = NULL;
	host->response[0] = 0;
	host->responseLen = 0;
	host->webDone = 0;

	if (hTempRequest)
		WinHttpCloseHandle(hTempRequest);

	if (hTempConnect)
		WinHttpCloseHandle(hTempConnect);

}

static void WEB_ResetWebList_WinHttp(void)
{
	int i;	
	webList_t *host;

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		WEB_ResetWebList_WinHttp_Single(host, qtrue);
	}
	webActive = 0;
}

// ====== Init - just add the flag and callback ======
static void WEB_Init_WinHttp(void)
{
	wchar_t wUserAgent[128] = { 0 };
	DWORD dwProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
	DWORD dwMaxConns = 1;
	DWORD_PTR empty = 0;

	swprintf_s(wUserAgent, 128, L"KingpinMaster/%S", KP_MASTER_VERSION);

	// KEY CHANGE: pass WINHTTP_FLAG_ASYNC
	hGlobalSession = WinHttpOpen(wUserAgent,
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		WINHTTP_FLAG_ASYNC);  // <- this

	if (hGlobalSession)
	{
		WinHttpSetOption(hGlobalSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
							&dwProtocols, sizeof(dwProtocols));
		WinHttpSetOption(hGlobalSession, WINHTTP_OPTION_MAX_CONNS_PER_SERVER,
							&dwMaxConns, sizeof(dwMaxConns));

		// KEY CHANGE: register the callback
		WinHttpSetStatusCallback(hGlobalSession,
			(WINHTTP_STATUS_CALLBACK)WEB_Callback_WinHttp,
			WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, //WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
			empty);

		// KEY CHANGE: no more CreateThread / CreateEvent per host
		for (int i = 0; i < MAX_WEBLIST; i++)
		{
			webHostList[i].url[0] = '\0';
			webHostList[i].webDone = 0;
			webHostList[i].webError = 0;
			webHostList[i].responseLen = 0;
		}
	}
}

static void WEB_Shutdown_WinHttp(void)
{
	DWORD_PTR empty = 0;
	webList_t *host;

	if (hGlobalSession)
	{
		for (int i = 0; i < MAX_WEBLIST; i++)
		{
			host = &webHostList[i];
			WEB_ResetWebList_WinHttp_Single(host, qtrue);
		}

		// Unregister callback FIRST so no in-flight callback
		// fires after we close the session
		WinHttpSetStatusCallback(hGlobalSession, NULL, 0, empty);
		Sleep(10);
		WinHttpCloseHandle(hGlobalSession);
		Sleep(10);
		hGlobalSession = NULL;
	}
}


#endif // end winHttp


#if 1 //curl
static size_t WEB_WriteCallback(char *data, size_t size, size_t nmemb, void *userptr)
{
	size_t total = size * nmemb;
	webList_t *host = (webList_t *)userptr;
	size_t offset = host->responseLen;

	//full? compensate last null
	if (offset >= MAX_PACKET_SIZE_RECV -1)
		return 0; // signal curl to abort (buffer full)

	if (offset + total >= MAX_PACKET_SIZE_RECV)
		total =  (MAX_PACKET_SIZE_RECV-1) - offset;

	if (total > 0)
	{
		memcpy(host->response + offset, data, total);
		host->responseLen += total;
		host->response[host->responseLen] = '\0';
	}
	return size * nmemb;
}


static void WEB_SendQueryToWebHost_Curl()
{
	int i;
	char userAgent[128];
	CURL  *curl;
	webList_t *host;

	sprintf(userAgent, "KingpinMaster/%s", KP_MASTER_VERSION);

	//gCurl.curl_easy_setopt(c, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");   

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (host->url[0] == '\0')
			continue;

		host->webCurl = gCurl.curl_easy_init();
		if (!host->webCurl)
			continue;

		curl = host->webCurl;

		// build URL: http://host:port/file

		gCurl.curl_easy_setopt(curl, CURLOPT_URL, host->url);
		gCurl.curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WEB_WriteCallback);
		gCurl.curl_easy_setopt(curl, CURLOPT_WRITEDATA, host);
		gCurl.curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
		gCurl.curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
		gCurl.curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // required for multi on Windows
		gCurl.curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent);
		gCurl.curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 300);
		gCurl.curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
		gCurl.curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

		//ssl cert
#if 0
		gCurl.curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
		gCurl.curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA); 
#else
		gCurl.curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		gCurl.curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

		//debug
		//gCurl.curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);   

		if (gCurl.curl_multi_add_handle(webMulti, curl) == CURLM_OK)
		{
			host->active = qtrue;
			host->responseLen = 0;
			host->response[0] = 0;
			webActive++;
		}
		else
		{
			// Cleanup the dead handle immediately if the multi-pool rejects it
			gCurl.curl_easy_cleanup(curl);
			host->webCurl = NULL;
		}
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
	gCurl.curl_multi_perform(webMulti, &still_running);

	// empty queue
	while ((msg = gCurl.curl_multi_info_read(webMulti, &msgs_left)) != NULL)
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
					host->url, gCurl.curl_easy_strerror(msg->data.result));

				// only print if something actually came through
				if (host->responseLen > 0)
					MsgPrint(MSG_DEBUG, "WEBLIST: partial: [%s]\n", host->response);
			}
			else
			{
				long http_code = 0;
				gCurl.curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);

				if (http_code >= 400)
				{
					MsgPrint(MSG_WARNING, "WEBLIST: %s returned HTTP error %ld\n", host->url, http_code);
					host->webError = (DWORD)http_code;
				}
				else
				{
					MsgPrint(MSG_DEBUG, "WEBLIST: got %d bytes from %s\n",
						(int)host->responseLen, host->url);

					// dump the actual response
					MsgPrint(MSG_DEBUG | MSG_COL_3_BROWN, "WEBLIST: [%s]\n", 
						host->response);

					//read the ip lists
					WEB_ProcessWebRecData(i);
				}
			}

			gCurl.curl_multi_remove_handle(webMulti, host->webCurl);
			gCurl.curl_easy_cleanup(host->webCurl);
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


static void WEB_ResetWebList_Curl()
{
	int i;
	webList_t *host;

	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];

		if (host->webCurl)
		{
			gCurl.curl_multi_remove_handle(webMulti, host->webCurl);
			gCurl.curl_easy_cleanup(host->webCurl);
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


static void WEB_Shutdown_Curl() 
{
	int i;
	webList_t *host;

	// clean up any remaining handles first
	for (i = 0; i < MAX_WEBLIST; i++)
	{
		host = &webHostList[i];
		if (host->webCurl)
		{
			gCurl.curl_multi_remove_handle(webMulti, host->webCurl);
			gCurl.curl_easy_cleanup(host->webCurl);
			host->webCurl = NULL;
		}
	}

	gCurl.curl_multi_cleanup(webMulti);
	gCurl.curl_global_cleanup();
}
#endif //end curl


static void WEB_SendQueryToWebHost()
{
	if (useCurl)
		WEB_SendQueryToWebHost_Curl();
#if defined(WIN32)
	else
		WEB_SendQueryToWebHost_WinHttp();
#endif
}


// ---------- Public functions ---------- //

void WEB_PollWebList(void)
{
	Sv_MemCheck("WEB_Poll start");

	if (useCurl)
		WEB_PollCurl();
#if defined(WIN32)
	else
		WEB_PollWinHttp();
#endif

	Sv_MemCheck("WEB_Poll end");
}

void WEB_ResetWebList()
{
	if (useCurl)
		WEB_ResetWebList_Curl();
#if defined(WIN32)
	else
		WEB_ResetWebList_WinHttp();
#else

#endif
}

/*
====================
WEB_Begin_Send

Load WebList
====================
*/
void WEB_Begin_Send()
{
	Sv_MemCheck("WEB_Begin_Send start");

	isWebGSPort = !isWebGSPort; //switch between GSpy and Gameport

	WEB_ResetWebList();

	//open weblist.txt. if valid, send packet
	if (WEB_ParseFile(isWebGSPort))
	{
		WEB_SendQueryToWebHost();
	}

	Sv_MemCheck("WEB_Begin_Send end");
}


//startup
void WEB_Init()
{
	MsgPrint(MSG_NORMAL, "-==========================================-\n");

	if (WEBCURL_init())
	{
		curl_version_info_data *version_data = gCurl.curl_version_info(CURLVERSION_NOW);
		useCurl = qtrue;
		webMulti = gCurl.curl_multi_init();
	
		MsgPrint(MSG_NORMAL|MSG_COL_3_BROWN, 
			"CURL:              Library Loaded.\n"
			"CURL Version:      %s\n" 
			"CURL SSL Version:  %s\n", 
			version_data->version, 
			version_data->ssl_version);
	}
	else
	{
		MsgPrint(MSG_WARNING, "CURL:    loading library failed.\n");
	}

#if defined(WIN32)
	if (!useCurl)
	{	
		MsgPrint(MSG_WARNING, "WINHTTP: loading library.\n");
		WEB_Init_WinHttp();
	}
#endif
	MsgPrint(MSG_NORMAL, "-==========================================-\n");
}

void WEB_Shutdown()
{
	if (useCurl)
		WEBCURL_shutdown();
#if defined(WIN32)
	else
		WEB_Shutdown_WinHttp();
#endif
}
