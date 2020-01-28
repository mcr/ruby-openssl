/*
 * 'OpenSSL for Ruby' project
 * clone from ossl_ssl.c by Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2017 Michael Richardson <mcr@sandelman.ca>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#include <openssl/bio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <string.h>

VALUE cDTLSContext;
VALUE cDTLSSocket;
static VALUE eSSLError;
extern VALUE cSSLContext;
static int ossl_dtlsctx_ex_ptr_idx;  /* suspect this should be shared with ssl*/
extern int ossl_ssl_ex_vcb_idx;

extern const rb_data_type_t ossl_sslctx_type;

extern ID id_i_verify_callback;

unsigned int cookie_secret_set = 0;
unsigned char cookie_secret[16];

enum connecting {
  NOT_CONNECTED=0,
  CONNECTED = 1
};

/*
 * generate a stateless cookie by creating a keyed HMAC-SHA256 for the cookie.
 * 1) The key is randomly generated if not already set and is kept constant.
 * 2) The contents of the hash come from:
 *      a) the current time in seconds since epoch with the low
 *         byte forced to zero, so new cookies occur every 2.5 minutes.
 *      b) the originating IP address and port number, taken from
 *         SSL in network byte order.
 */

static void cookie_secret_setup(void)
{
  if(!cookie_secret_set) {
    if(RAND_bytes(cookie_secret, sizeof(cookie_secret)) == 1) {
      cookie_secret_set = 1;
    }
  }
}

#define DTLS_COOKIE_DEBUG 0
#define DTLS_DEBUG 0

#if DTLS_COOKIE_DEBUG
static void print_cookie(const char *label, const unsigned char cookie[], const unsigned int cookie_len)
{
  unsigned int i;
  printf("%s cookie: ", label);
  for(i=0; i<cookie_len; i++) {
    printf("%02x ", cookie[i]);
  }
  printf("\n");
}
#define PRINT_COOKIE(label, cookie, len) print_cookie(label, cookie,len)
#else
#define PRINT_COOKIE(label, cookie, len) {} while(0)
#endif

#if HAVE_DTLSV1_ACCEPT
static void cookie_calculate(unsigned char cookie[],
                             unsigned int  *cookie_len,
                             BIO_ADDR *peer,
                             const time_t         curtime)
{
    unsigned char things_to_crunch[256];
    int           things_len = 0;
    const struct sockaddr *peersock = BIO_ADDR_sockaddr(peer);
    const unsigned char *addrdata;
    unsigned int   addrlen;
    unsigned short peerport;

    switch(peersock->sa_family) {
    case AF_INET:
      addrdata = (unsigned char *)&((struct sockaddr_in *)peersock)->sin_addr;
      addrlen  = 4;
      break;

    case AF_INET6:
      addrdata = ((struct sockaddr_in6 *)peersock)->sin6_addr.s6_addr;
      addrlen  = 16;
      break;

    default:
      addrdata = (unsigned char *)"";
      addrlen  = 0;
    }

    peerport = BIO_ADDR_rawport(peer);

   /* 24 bits of time is enough */
    PRINT_COOKIE("time",  (unsigned char *)&curtime, 4);
    things_to_crunch[0] = (curtime >> 24) & 0xff;
    things_to_crunch[1] = (curtime >> 16) & 0xff;
    things_to_crunch[2] = (curtime >>  8) & 0xff;
    things_to_crunch[3] = 0;
    PRINT_COOKIE("port",  (unsigned char *)&peerport, 2);
    things_to_crunch[4] = (peerport >> 8) & 0xff;
    things_to_crunch[5] = (peerport >> 0) & 0xff;
    things_len = 6;
    PRINT_COOKIE("addr", addrdata, addrlen);
    memcpy(things_to_crunch + things_len, addrdata, addrlen);
    things_len += addrlen;

    PRINT_COOKIE("scrt", cookie_secret, sizeof(cookie_secret));
    HMAC(EVP_sha256(),
         cookie_secret, sizeof(cookie_secret),
         things_to_crunch, things_len,
         cookie, cookie_len);

    PRINT_COOKIE("calculated  ", cookie, *cookie_len);
}

static int cookie_gen(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned int i;
    unsigned char cookie1[EVP_MAX_MD_SIZE];
    unsigned int  cookie1_len;
    struct timeval tv;
    BIO_ADDR   *peer;
    BIO *rbio;
    int  ret;

    cookie_secret_setup();
    gettimeofday(&tv, NULL);

    rbio = SSL_get_rbio(ssl);
    peer = BIO_ADDR_new();
    if(rbio == NULL || BIO_dgram_get_peer(rbio, peer) <= 0) {
      ret = 0;
      goto err;
    }

    cookie1_len = sizeof(cookie1);
    cookie_calculate(cookie1, &cookie1_len, peer,
                     tv.tv_sec);

    for (i = 0; i<DTLS1_COOKIE_LENGTH && i<cookie1_len; i++) {
      cookie[i] = cookie1[i];
    }
    *cookie_len = i;
    ret = 1;

    PRINT_COOKIE("generated  ", cookie, *cookie_len);

 err:
    if(peer) BIO_ADDR_free(peer);
    return ret;
}

static int cookie_verify(SSL *ssl, const unsigned char *peer_cookie,
                         unsigned int peer_cookie_len)
{
    unsigned char cookie1[EVP_MAX_MD_SIZE];
    unsigned int  cookie1_len;
    struct timeval tv;
    BIO_ADDR   *peer;
    BIO *rbio;
    int  ret = 0;

    PRINT_COOKIE("peer cookie", peer_cookie, peer_cookie_len);

    cookie_secret_setup();
    gettimeofday(&tv, NULL);

    rbio = SSL_get_rbio(ssl);
    peer = BIO_ADDR_new();
    if(rbio == NULL || BIO_dgram_get_peer(rbio, peer) <= 0) {
      ret = 0;
      goto out;
    }

    cookie1_len = sizeof(cookie1);
    cookie_calculate(cookie1, &cookie1_len,  peer, tv.tv_sec);

    if(cookie1_len != peer_cookie_len) {
      /* cookies lengths must match! */
      goto out;
    }

    if(memcmp(cookie1, peer_cookie, cookie1_len) == 0) {
      /* matches exactly */
      ret = 1;
      goto out;
    }

    /* if clock&0xff < 128, then try previous period */
    if((tv.tv_sec & 0xff) < 128) {
      tv.tv_sec -= 256;

      cookie1_len = sizeof(cookie1);
      cookie_calculate(cookie1, &cookie1_len, peer,
                       tv.tv_sec);

      if(memcmp(cookie1, peer_cookie, cookie1_len) == 0) {
        /* matches exactly */
        ret = 1;
      }
    }

 out:
    if(peer) BIO_ADDR_free(peer);
    return ret;
}
#endif /* HAVE_DTLSV1_ACCEPT */


static VALUE
ossl_dtlsctx_s_alloc(VALUE klass)
{
    SSL_CTX *ctx;
    long mode = 0 |
	SSL_MODE_ENABLE_PARTIAL_WRITE |
	SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
	SSL_MODE_RELEASE_BUFFERS;
    VALUE obj;

    obj = TypedData_Wrap_Struct(klass, &ossl_sslctx_type, 0);
    ctx = SSL_CTX_new(DTLS_method());
    if (!ctx) {
        ossl_raise(eSSLError, "DTLS_CTX_new");
    }
    SSL_CTX_set_mode(ctx, mode);
    RTYPEDDATA_DATA(obj) = ctx;
    SSL_CTX_set_ex_data(ctx, ossl_dtlsctx_ex_ptr_idx, (void *)obj);

#if HAVE_DTLSV1_ACCEPT
    SSL_CTX_set_cookie_generate_cb(ctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify);
#endif

#if !defined(OPENSSL_NO_EC) && defined(HAVE_SSL_CTX_SET_ECDH_AUTO)
    /* We use SSL_CTX_set1_curves_list() to specify the curve used in ECDH. It
     * allows to specify multiple curve names and OpenSSL will select
     * automatically from them. In OpenSSL 1.0.2, the automatic selection has to
     * be enabled explicitly. But OpenSSL 1.1.0 removed the knob and it is
     * always enabled. To uniform the behavior, we enable the automatic
     * selection also in 1.0.2. Users can still disable ECDH by removing ECDH
     * cipher suites by SSLContext#ciphers=. */
    if (!SSL_CTX_set_ecdh_auto(ctx, 1))
	ossl_raise(eSSLError, "DTLS_CTX_set_ecdh_auto");
#endif

    return obj;
}

#ifndef OPENSSL_NO_SOCK
static VALUE
ossl_dtls_setup(VALUE self, enum connecting connecting)
{
    VALUE io;
    SSL *ssl;
    rb_io_t *fptr;
    BIO *bio = NULL;

    GetSSL(self, ssl);
    if (ssl_started(ssl))
	return Qtrue;

    io = rb_attr_get(self, id_i_io);
    GetOpenFile(io, fptr);
    rb_io_check_readable(fptr);
    rb_io_check_writable(fptr);

    //printf("dtls setup for fd: %d\n", TO_SOCKET(fptr->fd));
    bio = BIO_new_dgram(TO_SOCKET(fptr->fd), BIO_NOCLOSE);
    if(bio == NULL) {
      ossl_raise(eSSLError, "ossl_dtls_setup");
    }
    if(connecting) {
      BIO_ADDR *peer = BIO_ADDR_new();
      if(peer) {
        (void)BIO_dgram_get_peer(bio, peer);
        (void)BIO_ctrl_set_connected(bio, peer);
        BIO_ADDR_free(peer);
      }
    }
    SSL_set_bio(ssl, bio, bio);

    return Qtrue;
}

#if HAVE_DTLSV1_ACCEPT
/*
 * call-seq:
 *    ssl.accept => self
 *
 * Looks at the incoming (bind(), but not connect()) socket for new incoming
 * DTLS connections, and return a new SSL context for the resulting connection.
 *
 * This uses an OpenSSL extension DTLSv1_accept(), which handles cloning the
 * the file descriptor and creating a new SSL context.
 */
static VALUE
ossl_dtls_start_accept(VALUE self, VALUE io, VALUE opts)
{
    int nonblock = opts != Qfalse;
    SSL *ssl;
    SSL *sslnew;
    BIO_ADDR   *peer;
    rb_io_t *fptr, *nsock;
    VALUE dtls_child, ret_value = Qnil;
    int ret;
    VALUE v_ctx, verify_cb;
    int one         = 1;

    /* extract the Ruby wrapper for the context for later on */
    v_ctx = rb_ivar_get(self, id_i_context);

    /* make sure it's all setup */
    ossl_dtls_setup(self, NOT_CONNECTED);

    GetSSL(self, ssl);
    GetOpenFile(rb_attr_get(self, id_i_io), fptr);
    GetOpenFile(io, nsock);

    /* allocate a new SSL* for the connection */
    sslnew = SSL_new(SSL_get_SSL_CTX(ssl));

    peer = BIO_ADDR_new();

    if(setsockopt(fptr->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
      goto end;
    }
    if(setsockopt(nsock->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
      goto end;
    }

    ret = 0;
    while(ret == 0) {
      ret = DTLSv1_accept(ssl, sslnew, peer, nsock->fd);

      if(ret == 0) {
        if(DTLS_DEBUG) printf("returned 0, waiting for more data\n");
        if (no_exception_p(opts)) { return sym_wait_readable; }
        read_would_block(nonblock);
        rb_io_wait_readable(fptr->fd);
      }
    }

    if(ret == -1) {
      /* this is an error */
      ossl_raise(eSSLError, "%s SYSCALL returned=%d errno=%d state=%s", "DTLSv1_listen", ret, errno, SSL_state_string_long(ssl));
      return self;
    }

    if(ret != 1) {
      /* this is no data present, would block */
      if(DTLS_DEBUG) printf("DTLSv1_accept returned: %d (needs data, block)\n", ret);
      return Qnil;
    }

#if DTLS_DEBUG
    /* a return of 1 means that a connection is present */
    {
      char *peername= BIO_ADDR_hostname_string(peer, 1);
      if(peername) {
        printf("peername: %s\n", peername);
        OPENSSL_free(peername);
      }
    }
#endif

    /* sslnew contains an initialized SSL, which has a new socket connected to it */

    /* new_sock is now setup, need to allocate new SSL context and insert socket into new bio */
    /* create a new ruby object */
    dtls_child = TypedData_Wrap_Struct(cDTLSSocket, &ossl_ssl_type, NULL);

    /* connect them up. */
    if (!sslnew)
      ossl_raise(eSSLError, NULL);
    RTYPEDDATA_DATA(dtls_child) = sslnew;

    /* setup a new IO object for the FD attached to the dtls_child */
    rb_ivar_set(dtls_child, id_i_io, io);

    SSL_set_ex_data(sslnew, ossl_ssl_ex_ptr_idx, (void *)dtls_child);
    SSL_set_info_callback(sslnew, ssl_info_cb);
    verify_cb = rb_attr_get(v_ctx, id_i_verify_callback);
    SSL_set_ex_data(sslnew, ossl_ssl_ex_vcb_idx, (void *)verify_cb);

    /* start the DTLS on it */
    ret_value = ossl_start_ssl(dtls_child, SSL_accept, "SSL_accept", Qfalse);

    if(DTLS_DEBUG) printf("completed ossl_start_ssl\n");

 end:
    if(peer) BIO_ADDR_free(peer);
    peer = NULL;

    return ret_value;
}

static VALUE
ossl_dtls_accept(int argc, VALUE *argv, VALUE self)
{
    VALUE io;

    rb_scan_args(argc, argv, "1", &io);
    ossl_dtls_setup(self, NOT_CONNECTED);

    return ossl_dtls_start_accept(self, io, Qfalse);
}

/*
 * call-seq:
 *    ssl.accept_nonblock([options]) => self
 *
 * Initiates the SSL/TLS handshake as a server in non-blocking manner.
 *
 *   # emulates blocking accept
 *   begin
 *     ssl.accept_nonblock
 *   rescue IO::WaitReadable
 *     IO.select([s2])
 *     retry
 *   rescue IO::WaitWritable
 *     IO.select(nil, [s2])
 *     retry
 *   end
 *
 * By specifying a keyword argument _exception_ to +false+, you can indicate
 * that accept_nonblock should not raise an IO::WaitReadable or
 * IO::WaitWritable exception, but return the symbol +:wait_readable+ or
 * +:wait_writable+ instead.
 */
static VALUE
ossl_dtls_accept_nonblock(int argc, VALUE *argv, VALUE self)
{
    VALUE opts;
    VALUE io;

    rb_scan_args(argc, argv, "1:", &io, &opts);
    ossl_dtls_setup(self, NOT_CONNECTED);

    return ossl_dtls_start_accept(self, io, opts);
}
#endif

/*
 * call-seq:
 *    ssl.connect_nonblock([options]) => self
 *
 * Initiates the DTLS handshake as a client in non-blocking manner.
 *
 *   # emulates blocking connect
 *   begin
 *     ssl.connect_nonblock
 *   rescue IO::WaitReadable
 *     IO.select([s2])
 *     retry
 *   rescue IO::WaitWritable
 *     IO.select(nil, [s2])
 *     retry
 *   end
 *
 * By specifying a keyword argument _exception_ to +false+, you can indicate
 * that connect_nonblock should not raise an IO::WaitReadable or
 * IO::WaitWritable exception, but return the symbol +:wait_readable+ or
 * +:wait_writable+ instead.
 */
static VALUE
ossl_dtls_connect_nonblock(int argc, VALUE *argv, VALUE self)
{
    VALUE opts;
    rb_scan_args(argc, argv, "0:", &opts);

    ossl_dtls_setup(self, CONNECTED);

    return ossl_start_ssl(self, SSL_connect, "SSL_connect_nonblock", opts);
}

/*
 * call-seq:
 *    ssl.connect => self
 *
 * Initiates an DTLS handshake with a server.  The handshake may be started
 * after unencrypted data has been sent over the socket.
 */
static VALUE
ossl_dtls_connect(VALUE self)
{
  ossl_dtls_setup(self, CONNECTED);

  return ossl_start_ssl(self, SSL_connect, "SSL_connect", Qfalse);
}


#endif /* !defined(OPENSSL_NO_SOCK) */

#undef rb_intern
#define rb_intern(s) rb_intern_const(s)
void
Init_ossl_dtls(void)
{
    /* Document-module: OpenSSL::SSL
     *
     * Use SSLContext to set up the parameters for a TLS (former SSL)
     * connection. Both client and server TLS connections are supported,
     * SSLSocket and SSLServer may be used in conjunction with an instance
     * of SSLContext to set up connections.
     */
    mSSL = rb_define_module_under(mOSSL, "SSL");
    eSSLError = rb_define_class_under(mSSL, "SSLError", eOSSLError);

    /* Document-class: OpenSSL::SSL::DTLSContext
     *
     * A DTLSContext is used to set various options regarding certificates,
     * algorithms, verification, session caching, etc.  The DTLSContext is
     * used to create a DTLSSocket.
     *
     * All attributes must be set before creating a DTLSSocket as the
     * DTLSContext will be frozen afterward.
     */
    cDTLSContext = rb_define_class_under(mSSL, "DTLSContext", cSSLContext);
    rb_define_alloc_func(cDTLSContext, ossl_dtlsctx_s_alloc);
    rb_undef_method(cDTLSContext, "initialize_copy");

    cDTLSSocket = rb_define_class_under(mSSL, "DTLSSocket", cSSLSocket);
#ifdef HAVE_DTLSV1_ACCEPT
    rb_define_method(cDTLSSocket, "accept",          ossl_dtls_accept, -1);
    rb_define_method(cDTLSSocket, "accept_nonblock", ossl_dtls_accept_nonblock, -1);
#endif
    rb_define_method(cDTLSSocket, "connect",         ossl_dtls_connect, 0);
    rb_define_method(cDTLSSocket, "connect_nonblock",ossl_dtls_connect_nonblock, -1);

    //printf("\n\nsetting cDTLSSocket.accept to %p\n", ossl_dtls_accept);
}
