/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_SSL_H_)
#define _OSSL_SSL_H_

#define GetSSL(obj, ssl) do { \
	TypedData_Get_Struct((obj), SSL, &ossl_ssl_type, (ssl)); \
	if (!(ssl)) { \
		ossl_raise(rb_eRuntimeError, "SSL is not initialized"); \
	} \
} while (0)

#define GetSSLSession(obj, sess) do { \
	TypedData_Get_Struct((obj), SSL_SESSION, &ossl_ssl_session_type, (sess)); \
	if (!(sess)) { \
		ossl_raise(rb_eRuntimeError, "SSL Session wasn't initialized."); \
	} \
} while (0)

extern const rb_data_type_t ossl_ssl_type;
extern const rb_data_type_t ossl_ssl_session_type;
extern VALUE mSSL;
extern VALUE cSSLSocket;
extern VALUE cSSLSession;
extern int ossl_ssl_ex_ptr_idx;
extern void ssl_info_cb(const SSL *ssl, int where, int val);


#ifdef _WIN32
#  define TO_SOCKET(s) _get_osfhandle(s)
#else
#  define TO_SOCKET(s) (s)
#endif

static inline int
ssl_started(SSL *ssl)
{
    /* the FD is set in ossl_ssl_setup(), called by #connect or #accept */
    return SSL_get_fd(ssl) >= 0;
}

extern ID id_i_io, id_i_context, id_i_hostname;

extern VALUE ossl_start_ssl(VALUE self, int (*func)(),
                            const char *funcname, VALUE opts);

extern int no_exception_p(VALUE opts);
extern void read_would_block(int nonblock);
extern VALUE sym_exception, sym_wait_readable, sym_wait_writable;

void Init_ossl_ssl(void);
void Init_ossl_ssl_session(void);

#endif /* _OSSL_SSL_H_ */
