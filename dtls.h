/*******************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *    Achim Kraus    - session recovery
 *
 *******************************************************************************/

/**
 * @file dtls.h
 * @brief High level DTLS API and visible structures.
 */


#ifndef _DTLS_DTLS_H_
#define _DTLS_DTLS_H_

#include <stdint.h>

#include "dtls-state.h"
#include "dtls-peer.h"

#include "dtls-alert.h"
#include "dtls-crypto.h"
#include "dtls-hmac.h"

#include "tinydtls.h"

#ifndef DTLSv12
#define DTLS_VERSION 0xfeff	/* DTLS v1.1 */
#else
#define DTLS_VERSION 0xfefd	/* DTLS v1.2 */
#endif

#define seed_len 32
#define K_len 32




typedef enum dtls_credentials_type_t {
  DTLS_PSK_HINT, DTLS_PSK_IDENTITY, DTLS_PSK_KEY
} dtls_credentials_type_t;

typedef struct dtls_ecdsa_key_t {
  dtls_ecdh_curve curve;
  const unsigned char *priv_key;	/** < private key as bytes > */
  const unsigned char *pub_key_x;	/** < x part of the public key for the given private key > */
  const unsigned char *pub_key_y;	/** < y part of the public key for the given private key > */
} dtls_ecdsa_key_t;

/** Length of the secret that is used for generating Hello Verify cookies. */
#define DTLS_COOKIE_SECRET_LENGTH 12

struct dtls_context_t;


//Added By Simpy
static char *dtls_state_to_name(int state)
{
    switch (state) {

        case 0:  //type = 0
            return "DTLS_STATE_INIT";

        case 1:
            return "DTLS_STATE_WAIT_CLIENTHELLO";

        case 2:
            return "DTLS_STATE_WAIT_CLIENTCERTIFICATE";

        case 3:
            return "DTLS_STATE_WAIT_CLIENTKEYEXCHANGE";

        case 4:
            return "DTLS_STATE_WAIT_CERTIFICATEVERIFY";

        case 5:
            return "DTLS_STATE_WAIT_CHANGECIPHERSPEC";

        case 6:
            return "DTLS_STATE_WAIT_FINISHED";

        case 7:
            return "DTLS_STATE_FINISHED";

/* client states */

        case 8:
            return "DTLS_STATE_CLIENTHELLO";

        case 9:
            return "DTLS_STATE_WAIT_SERVERCERTIFICATE";

        case 10:
            return "DTLS_STATE_WAIT_SERVERKEYEXCHANGE";

        case 11:
            return "DTLS_STATE_WAIT_SERVERHELLODONE";

        case 12:
            return "DTLS_STATE_CONNECTED";

        case 13:
            return "DTLS_STATE_CLOSING";

        case 14:
            return "DTLS_STATE_CLOSED";

        default:
            return "unknown";
    }
}



/**
 * This structure contains callback functions used by tinydtls to
 * communicate with the application. At least the write function must
 * be provided. It is called by the DTLS state machine to send packets
 * over the network. The read function is invoked to deliver decrypted
 * and verfified application data. The third callback is an event
 * handler function that is called when alert messages are encountered
 * or events generated by the library have occured.
 */ 
typedef struct {
  /** 
   * Called from dtls_handle_message() to send DTLS packets over the
   * network. The callback function must use the network interface
   * denoted by session->ifindex to send the data.
   *
   * @param ctx  The current DTLS context.
   * @param session The session object, including the address of the
   *              remote peer where the data shall be sent.
   * @param buf  The data to send.
   * @param len  The actual length of @p buf.
   * @return The callback function must return the number of bytes 
   *         that were sent, or a value less than zero to indicate an 
   *         error.
   */
  int (*write)(struct dtls_context_t *ctx,
	       session_t *session, uint8_t *buf, size_t len);

  /**
   * Called from dtls_handle_message() deliver application data that was 
   * received on the given session. The data is delivered only after
   * decryption and verification have succeeded. 
   *
   * @param ctx  The current DTLS context.
   * @param session The session object, including the address of the
   *              data's origin. 
   * @param buf  The received data packet.
   * @param len  The actual length of @p buf.
   * @return ignored
   */
  int (*read)(struct dtls_context_t *ctx, 
	       session_t *session, uint8_t *buf, size_t len);

  /**
   * The event handler is called when a message from the alert
   * protocol is received or the state of the DTLS session changes.
   *
   * @param ctx     The current dtls context.
   * @param session The session object that was affected.
   * @param level   The alert level or @c 0 when an event ocurred that 
   *                is not an alert. 
   * @param code    Values less than @c 256 indicate alerts, while
   *                @c 256 or greater indicate internal DTLS session changes.
   * @return ignored
   */
  int (*event)(struct dtls_context_t *ctx, session_t *session, 
		dtls_alert_level_t level, unsigned short code);

#ifdef DTLS_PSK
  /**
   * Called during handshake to get information related to the
   * psk key exchange. The type of information requested is
   * indicated by @p type which will be one of DTLS_PSK_HINT,
   * DTLS_PSK_IDENTITY, or DTLS_PSK_KEY. The called function
   * must store the requested item in the buffer @p result of
   * size @p result_length. On success, the function must return
   * the actual number of bytes written to @p result, of a
   * value less than zero on error. The parameter @p desc may
   * contain additional request information (e.g. the psk_identity
   * for which a key is requested when @p type == @c DTLS_PSK_KEY.
   *
   * @param ctx     The current dtls context.
   * @param session The session where the key will be used.
   * @param type    The type of the requested information.
   * @param desc    Additional request information
   * @param desc_len The actual length of desc.
   * @param result  Must be filled with the requested information.
   * @param result_length  Maximum size of @p result.
   * @return The number of bytes written to @p result or a value
   *         less than zero on error.
   */
  int (*get_psk_info)(struct dtls_context_t *ctx,
		      const session_t *session,
		      dtls_credentials_type_t type,
		      const unsigned char *desc, size_t desc_len,
		      unsigned char *result, size_t result_length);

#endif /* DTLS_PSK */

#ifdef DTLS_ECC
  /**
   * Called during handshake to get the server's or client's ecdsa
   * key used to authenticate this server or client in this 
   * session. If found, the key must be stored in @p result and 
   * the return value must be @c 0. If not found, @p result is 
   * undefined and the return value must be less than zero.
   *
   * If ECDSA should not be supported, set this pointer to NULL.
   *
   * Implement this if you want to provide your own certificate to 
   * the other peer. This is mandatory for a server providing ECDSA
   * support and optional for a client. A client doing DTLS client
   * authentication has to implementing this callback.
   *
   * @param ctx     The current dtls context.
   * @param session The session where the key will be used.
   * @param result  Must be set to the key object to used for the given
   *                session.
   * @return @c 0 if result is set, or less than zero on error.
   */
  int (*get_ecdsa_key)(struct dtls_context_t *ctx, 
		       const session_t *session,
		       const dtls_ecdsa_key_t **result);

  /**
   * Called during handshake to check the peer's pubic key in this
   * session. If the public key matches the session and should be
   * considerated valid the return value must be @c 0. If not valid,
   * the return value must be less than zero.
   *
   * If ECDSA should not be supported, set this pointer to NULL.
   *
   * Implement this if you want to verify the other peers public key.
   * This is mandatory for a DTLS client doing based ECDSA
   * authentication. A server implementing this will request the
   * client to do DTLS client authentication.
   *
   * @param ctx          The current dtls context.
   * @param session      The session where the key will be used.
   * @param other_pub_x  x component of the public key.
   * @param other_pub_y  y component of the public key.
   * @return @c 0 if public key matches, or less than zero on error.
   * error codes:
   *   return dtls_alert_fatal_create(DTLS_ALERT_BAD_CERTIFICATE);
   *   return dtls_alert_fatal_create(DTLS_ALERT_UNSUPPORTED_CERTIFICATE);
   *   return dtls_alert_fatal_create(DTLS_ALERT_CERTIFICATE_REVOKED);
   *   return dtls_alert_fatal_create(DTLS_ALERT_CERTIFICATE_EXPIRED);
   *   return dtls_alert_fatal_create(DTLS_ALERT_CERTIFICATE_UNKNOWN);
   *   return dtls_alert_fatal_create(DTLS_ALERT_UNKNOWN_CA);
   */
  int (*verify_ecdsa_key)(struct dtls_context_t *ctx, 
			  const session_t *session,
			  const unsigned char *other_pub_x,
			  const unsigned char *other_pub_y,
			  size_t key_size);
#endif /* DTLS_ECC */
} dtls_handler_t;

struct netq_t;

/** Holds global information of the DTLS engine. */
typedef struct dtls_context_t {
  unsigned char cookie_secret[DTLS_COOKIE_SECRET_LENGTH];
  dtls_tick_t cookie_secret_age; /**< the time the secret has been generated */

  dtls_peer_t *peers;		/**< peer hash map */

#ifdef DTLS_SUPPORT_CONF_CONTEXT_STATE
  DTLS_SUPPORT_CONF_CONTEXT_STATE support;
#endif /* DTLS_SUPPORT_CONF_CONTEXT_STATE */

  struct netq_t *sendqueue;     /**< the packets to send */

  void *app;                    /**< application-specific data */

  const dtls_handler_t *h;      /**< callback handlers */

  unsigned char readbuf[DTLS_MAX_BUF];

  //added by simpy
  tesla_request treq; //Added by Simpy
  tesla_sync tsync;  //Added by Simpy
    double rtt;



} dtls_context_t;

/** 
 * This function initializes the tinyDTLS memory management and must
 * be called first.
 */
void dtls_init(void);

/** 
 * Creates a new context object. The storage allocated for the new
 * object must be released with dtls_free_context(). */
dtls_context_t *dtls_new_context(void *app_data);

/** Releases any storage that has been allocated for \p ctx. */
void dtls_free_context(dtls_context_t *ctx);

#define dtls_set_app_data(CTX,DATA) ((CTX)->app = (DATA))
#define dtls_get_app_data(CTX) ((CTX)->app)

/** Sets the callback handler object for @p ctx to @p h. */
static inline void dtls_set_handler(dtls_context_t *ctx,
                                    const dtls_handler_t *h)
{
  ctx->h = h;
}

/**
 * Establishes a DTLS channel with the specified remote peer @p dst.
 * This function returns @c 0 if that channel already exists, a value
 * greater than zero when a new ClientHello message was sent, and
 * a value less than zero on error.
 *
 * @param ctx    The DTLS context to use.
 * @param dst    The remote party to connect to.
 * @return A value less than zero on error, greater or equal otherwise.
 */
int dtls_connect(dtls_context_t *ctx, const session_t *dst);

/**
 * Establishes a DTLS channel with the specified remote peer.
 * This function returns @c 0 if that channel already exists, a value
 * greater than zero when a new ClientHello message was sent, and
 * a value less than zero on error.
 *
 * @param ctx    The DTLS context to use.
 * @param peer   The peer object that describes the session.
 * @return A value less than zero on error, greater or equal otherwise.
 */
int dtls_connect_peer(dtls_context_t *ctx, dtls_peer_t *peer);

/**
 * Closes the DTLS connection associated with @p remote. This function
 * returns zero on success, and a value less than zero on error.
 */
int dtls_close(dtls_context_t *ctx, const session_t *remote);

int dtls_renegotiate(dtls_context_t *ctx, const session_t *dst);

/** 
 * Writes the application data given in @p buf to the peer specified
 * by @p session. 
 * 
 * @param ctx      The DTLS context to use.
 * @param session  The remote transport address and local interface.
 * @param buf      The data to write.
 * @param len      The actual length of @p data.
 * 
 * @return The number of bytes written or @c -1 on error.
 */
int dtls_write(struct dtls_context_t *ctx, session_t *session, 
	       uint8_t *buf, size_t len);

/**
 * Checks sendqueue of given DTLS context object for any outstanding
 * packets to be transmitted. 
 *
 * @param context The DTLS context object to use.
 * @param next    If not NULL, @p next is filled with the timestamp
 *  of the next scheduled retransmission, or @c 0 when no packets are
 *  waiting.
 * @param all     if all retransmissions or a single retransmission should be performed
 */
void dtls_check_retransmit(dtls_context_t *context, dtls_tick_t *next, int all);

#define DTLS_COOKIE_LENGTH 16


/**Content types*/
#define DTLS_CT_CHANGE_CIPHER_SPEC 20
#define DTLS_CT_ALERT              21
#define DTLS_CT_HANDSHAKE          22
#define DTLS_CT_APPLICATION_DATA   23


/** Generic header structure of the DTLS record layer. */
typedef struct __attribute__((__packed__)) {
  uint8_t content_type;		/**< content type of the included message : CCS, APP data, HS, Alert */
  uint8_t version[2];		/**< Protocol version */
  uint8_t epoch[2];	        /**< counter for cipher state changes */
  uint8_t sequence_number[6];   /**< sequence number */
  uint8_t length[2];		/**< length of the following fragment */
    //E for another record extension
  /* fragment */
 // uint8_t t_interval_id[4]; /** Tesla Interval index */
 // uint8_t dis_key[32];      /** Disclosed key 32 Bytes for the interval*/

                            /** TESLA HMAC 32 Bytes*/

} dtls_record_header_t;

/* Handshake types */

#define DTLS_HT_HELLO_REQUEST        0
#define DTLS_HT_CLIENT_HELLO         1
#define DTLS_HT_SERVER_HELLO         2
#define DTLS_HT_HELLO_VERIFY_REQUEST 3
#define DTLS_HT_CERTIFICATE         11
#define DTLS_HT_SERVER_KEY_EXCHANGE 12
#define DTLS_HT_CERTIFICATE_REQUEST 13
#define DTLS_HT_SERVER_HELLO_DONE   14
#define DTLS_HT_CERTIFICATE_VERIFY  15
#define DTLS_HT_CLIENT_KEY_EXCHANGE 16
#define DTLS_HT_FINISHED            20
#define DTLS_HT_TESLA_CLIENT        7 //Added by Simpy
#define DTLS_HT_TESLA_SERVER        9 //Added by Simpy
#define DTLS_HS_FRAGMENTED 		    -244 //

/** Header structure for the DTLS handshake protocol. */
typedef struct __attribute__((__packed__)) {
  uint8_t msg_type; /**< Type of handshake message  (one of DTLS_HT_) */
  uint8_t length[3];  /**< length of this message */
  uint8_t message_seq[2]; 	/**< Message sequence number */
  uint8_t fragment_offset[3];	/**< Fragment offset. */
  uint8_t fragment_length[3];	/**< Fragment length. */

  /* body */
} dtls_handshake_header_t;

/** Structure of the Client Hello message. */
typedef struct __attribute__((__packed__)) {
  uint8_t version[2];	  /**< Client version */
  uint8_t gmt_random[4];  /**< GMT time of the random byte creation */
  unsigned char random[28];	/**< Client random bytes */

  /* session id (up to 32 bytes) */
  /* cookie (up to 32 bytes) */
  /* cipher suite (2 to 2^16 -1 bytes) */
  /* compression method */

} dtls_client_hello_t;

/** Structure of the Hello Verify Request. */
typedef struct __attribute__((__packed__)) {
  uint8_t version[2];		/**< Server version */
  uint8_t cookie_length;	/**< Length of the included cookie */
  uint8_t cookie[];		/**< up to 32 bytes making up the cookie */
} dtls_hello_verify_t;  

#if 0
/** 
 * Checks a received DTLS record for consistency and eventually decrypt,
 * verify, decompress and reassemble the contained fragment for 
 * delivery to high-lever clients. 
 * 
 * \param state The DTLS record state for the current session. 
 * \param 
 */
int dtls_record_read(dtls_state_t *state, uint8_t *msg, int msglen);
#endif

/** 
 * Handles incoming data as DTLS message from given peer.
 *
 * @param ctx     The dtls context to use.
 * @param session The current session
 * @param msg     The received data
 * @param msglen  The actual length of @p msg.
 * @return A value less than zero on error, zero on success.
 */
int dtls_handle_message(dtls_context_t *ctx, session_t *session,
			uint8_t *msg, int msglen);

/**
 * Check if @p session is associated with a peer object in @p context.
 * This function returns a pointer to the peer if found, NULL otherwise.
 *
 * @param context  The DTLS context to search.
 * @param session  The remote address and local interface
 * @return A pointer to the peer associated with @p session or NULL if
 *  none exists.
 */
dtls_peer_t *dtls_get_peer(const dtls_context_t *context,
			   const session_t *session);

/**
 * Resets all connections with @p peer.
 *
 * @param context  The active DTLS context.
 * @param peer     The peer to reset.
 */
void dtls_reset_peer(dtls_context_t *context, dtls_peer_t *peer);

#endif /* _DTLS_DTLS_H_ */

/**
 * @author Olaf Bergmann, TZI Uni Bremen
 *
 * This library provides a very simple datagram server with DTLS
 * support. It is designed to support session multiplexing in
 * single-threaded applications and thus targets specifically on
 * embedded systems.
 *
 * @section license License
 *
 * This software is under the <a
 * href="http://www.opensource.org/licenses/mit-license.php">MIT License</a>.
 *
 * @subsection sha256 Aaron D. Gifford's SHA256 Implementation
 *
 * tinyDTLS provides HMAC-SHA256 with BSD-licensed code from Aaron D. Gifford,
 * see <a href="http://www.aarongifford.com/">www.aarongifford.com</a>.
 *
 * @subsection aes Rijndael Implementation From OpenBSD
 *
 * The AES implementation is taken from rijndael.{c,h} contained in the crypto
 * sub-system of the OpenBSD operating system. It is copyright by Vincent Rijmen, *
 * Antoon Bosselaers and Paulo Barreto. See <a
 * href="http://www.openbsd.org/cgi-bin/cvsweb/src/sys/crypto/rijndael.c">rijndael.c</a>
 * for License info.
 *
 */
