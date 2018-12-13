/*
 * lws-crypto-jwk
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int bits = 4096;
	enum lws_gencrypto_kty kty = LWS_GENCRYPTO_KTY_RSA;
	struct lws_jwk jwk;
	char key[4096];
	const char *curve = "P-256";

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, "-b")))
		bits = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, "-t"))) {
		if (!strcmp(p, "RSA"))
			kty = LWS_GENCRYPTO_KTY_RSA;
		else
			if (!strcmp(p, "OCT"))
				kty = LWS_GENCRYPTO_KTY_OCT;
			else
				if (!strcmp(p, "EC"))
					kty = LWS_GENCRYPTO_KTY_EC;
				else {
					lwsl_err("Unknown key type (must be "
						 "OCT, RSA or EC)\n");

					return 1;
				}
	}

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS JWK example\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, "-v")))
		curve = p;

	if (lws_jwk_generate(context, &jwk, kty, bits, curve)) {
		lwsl_err("lws_jwk_generate failed\n");

		return 1;
	}

	if (lws_jwk_export(&jwk, 1, key, sizeof(key)) < 0) {
		lwsl_err("lws_jwk_export failed\n");

		return 1;
	}

	if (lws_cmdline_option(argc, argv, "-c")) {
		const char *k = key;
		int seq = 0;

		while (*k) {
			if (*k == '{') {
				putchar('\"');
				putchar('{');
				putchar('\"');
				putchar('\n');
				putchar('\t');
				putchar('\"');
				k++;
				seq = 0;
				continue;
			}
			if (*k == '}') {
				putchar('\"');
				putchar('\n');
				putchar('\"');
				putchar('}');
				putchar('\"');
				putchar('\n');
				k++;
				seq = 0;
				continue;
			}
			if (*k == '\"') {
				putchar('\\');
				putchar('\"');
				seq += 2;
				k++;
				continue;
			}
			if (*k == ',') {
				putchar(',');
				putchar('\"');
				putchar('\n');
				putchar('\t');
				putchar('\"');
				k++;
				seq = 0;
				continue;
			}
			putchar(*k);
			seq++;
			if (seq >= 60) {
				putchar('\"');
				putchar('\n');
				putchar('\t');
				putchar(' ');
				putchar('\"');
				seq = 1;
			}
			k++;
		}

	} else
		puts(key);

	lws_jwk_destroy(&jwk);

	lws_context_destroy(context);

	return result;
}
