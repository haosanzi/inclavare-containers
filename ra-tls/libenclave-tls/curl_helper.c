#include "curl_helper.h"

static
size_t accumulate_function(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct buffer_and_size *s = (struct buffer_and_size *) userdata;
	s->data = (char *) realloc(s->data, s->len + size * nmemb);
	assert(s->data != NULL);
	memcpy(s->data + s->len, ptr, size * nmemb);
	s->len += size * nmemb;

	return size * nmemb;
}

void http_get(CURL *curl, const char *url, struct buffer_and_size *header,
	      struct buffer_and_size *body, struct curl_slist *request_headers,
	      char *request_body)
{
	curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, accumulate_function);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_function);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);

	if (request_headers) {
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);
	}
	if (request_body) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
	}

	CURLcode res = curl_easy_perform(curl);
	assert(res == CURLE_OK);
}
