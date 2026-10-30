
/* web_curl.h */

#ifndef __WEBCURL_H__
#define __WEBCURL_H__

#include <curl/curl.h>

typedef struct {
	CURLcode (*curl_global_init)(long);
	void     (*curl_global_cleanup)(void);
	CURL*    (*curl_easy_init)(void);
	void     (*curl_easy_cleanup)(CURL*);
	CURLcode (*curl_easy_setopt)(CURL*, CURLoption, ...);
	CURLcode (*curl_easy_perform)(CURL*);
	const char *(*curl_easy_strerror)(CURLcode);

	CURLM*  (*curl_multi_init)(void);
	int     (*curl_multi_add_handle)(CURLM*, CURL*);
	CURLMcode (*curl_multi_perform)(CURLM*, int*);
	CURLMsg *(*curl_multi_info_read)(CURLM*, int*);
	int     (*curl_multi_remove_handle)(CURLM*, CURL*);
	int     (*curl_multi_cleanup)(CURLM*);

	CURLcode (*curl_easy_getinfo)(CURL*, CURLINFO, ...);
	curl_version_info_data* (*curl_version_info)(CURLversion);
} webCurl_t;

extern webCurl_t gCurl;

/* Call once at startup */
int  WEBCURL_init(void);
void WEBCURL_shutdown(void);

#endif
