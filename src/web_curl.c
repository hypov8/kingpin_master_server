/* web_curl.c */

#include "web_curl.h"
#include "common.h"

//#include <windows.h>  /* only on Windows — guarded below */

webCurl_t gCurl;


#ifdef _WIN32
static HMODULE g_hCurl;

int WEBCURL_init(void)
{
	g_hCurl = LoadLibraryA("libcurl.dll");
	if (!g_hCurl) 
		return 0;

	gCurl.curl_global_init = (CURLcode(*)(long))                  GetProcAddress(g_hCurl, "curl_global_init");
	gCurl.curl_global_cleanup = (void(*)(void))                       GetProcAddress(g_hCurl, "curl_global_cleanup");
	gCurl.curl_easy_init = (CURL*(*)(void))                      GetProcAddress(g_hCurl, "curl_easy_init");
	gCurl.curl_easy_cleanup = (void(*)(CURL*))                       GetProcAddress(g_hCurl, "curl_easy_cleanup");
	gCurl.curl_easy_setopt = (CURLcode(*)(CURL*, CURLoption, ...))    GetProcAddress(g_hCurl, "curl_easy_setopt");
	gCurl.curl_easy_perform = (CURLcode(*)(CURL*))                   GetProcAddress(g_hCurl, "curl_easy_perform");
	gCurl.curl_easy_strerror = (const char*(*)(CURLcode))             GetProcAddress(g_hCurl, "curl_easy_strerror");

	gCurl.curl_multi_init           = (CURLM*(*)(void))                    GetProcAddress(g_hCurl, "curl_multi_init");
	gCurl.curl_multi_add_handle     = (int(*)(CURLM*,CURL*))               GetProcAddress(g_hCurl, "curl_multi_add_handle");
	gCurl.curl_multi_perform        = (CURLMcode(*)(CURLM*,int*))          GetProcAddress(g_hCurl, "curl_multi_perform");
	gCurl.curl_multi_info_read      = (CURLMsg*(*)(CURLM*,int*))           GetProcAddress(g_hCurl, "curl_multi_info_read");
	gCurl.curl_multi_remove_handle  = (int(*)(CURLM*,CURL*))               GetProcAddress(g_hCurl, "curl_multi_remove_handle");
	gCurl.curl_multi_cleanup        = (int(*)(CURLM*))                     GetProcAddress(g_hCurl, "curl_multi_cleanup");   

	gCurl.curl_easy_getinfo         = (CURLcode(*)(CURL*, CURLINFO, ...))  GetProcAddress(g_hCurl, "curl_easy_getinfo");
	gCurl.curl_version_info         = (curl_version_info_data* (*)(CURLversion))GetProcAddress(g_hCurl, "curl_version_info");


	// Ensure every mapped function is valid before declaring initialization a success
	if (!gCurl.curl_global_init || !gCurl.curl_global_cleanup ||
		!gCurl.curl_easy_init   || !gCurl.curl_easy_cleanup ||
		!gCurl.curl_easy_setopt || !gCurl.curl_easy_strerror ||
		!gCurl.curl_multi_init  || !gCurl.curl_multi_perform ||
		!gCurl.curl_easy_getinfo|| !gCurl.curl_version_info) 
	{
		// A function couldn't be loaded from the DLL - trigger WinHTTP fallback safely
		return 0;
	}


	return gCurl.curl_global_init(CURL_GLOBAL_WIN32) == CURLE_OK;
}

void WEBCURL_shutdown(void)
{
	if (g_hCurl) {
		gCurl.curl_global_cleanup();
		FreeLibrary(g_hCurl);
	}
}

#else  /* Linux / macOS */

int WEBCURL_init(void)
{
	gCurl.curl_global_init      = curl_global_init;
	gCurl.curl_global_cleanup   = curl_global_cleanup;
	gCurl.curl_easy_init        = curl_easy_init;
	gCurl.curl_easy_cleanup     = curl_easy_cleanup;
	gCurl.curl_easy_setopt      = curl_easy_setopt;
	gCurl.curl_easy_perform     = curl_easy_perform;
	gCurl.curl_easy_strerror    = curl_easy_strerror;

	gCurl.curl_multi_init           = curl_multi_init;
	gCurl.curl_multi_add_handle     = curl_multi_add_handle;
	gCurl.curl_multi_perform        = curl_multi_perform;
	gCurl.curl_multi_info_read      = curl_multi_info_read;
	gCurl.curl_multi_remove_handle  = curl_multi_remove_handle;
	gCurl.curl_multi_cleanup        = curl_multi_cleanup;   

	gCurl.curl_easy_getinfo         = curl_easy_getinfo;
	gCurl.curl_version_info = curl_version_info;

	return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}

void WEBCURL_shutdown(void)
{
	curl_global_cleanup();
}

#endif
