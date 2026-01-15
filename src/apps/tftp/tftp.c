/**
 *
 * @file tftp.c
 *
 * @author   Logan Gunthorpe <logang@deltatee.com>
 *           Dirk Ziegelmeier <dziegel@gmx.de>
 *
 * @brief    Trivial File Transfer Protocol (RFC 1350)
 *
 * Copyright (c) Deltatee Enterprises Ltd. 2013
 * All rights reserved.
 *
 */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification,are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Logan Gunthorpe <logang@deltatee.com>
 *         Dirk Ziegelmeier <dziegel@gmx.de>
 *
 */

/**
 * @defgroup tftp TFTP client/server
 * @ingroup apps
 *
 * This is simple TFTP client/server for the lwIP raw API.
 * You need to increase MEMP_NUM_SYS_TIMEOUT by one if you use TFTP!
 */

#include "lwip/apps/tftp_client.h"
#include "lwip/apps/tftp_server.h"

#if LWIP_UDP

#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"

#define TFTP_MAX_PAYLOAD_SIZE 512
#define TFTP_HEADER_LENGTH    4

/* RFC 2348 blksize option limits */
#define TFTP_BLKSIZE_MIN      8
#define TFTP_BLKSIZE_MAX      65464

#define TFTP_RRQ   1
#define TFTP_WRQ   2
#define TFTP_DATA  3
#define TFTP_ACK   4
#define TFTP_ERROR 5
#define TFTP_OACK  6

enum tftp_error {
  TFTP_ERROR_FILE_NOT_FOUND    = 1,
  TFTP_ERROR_ACCESS_VIOLATION  = 2,
  TFTP_ERROR_DISK_FULL         = 3,
  TFTP_ERROR_ILLEGAL_OPERATION = 4,
  TFTP_ERROR_UNKNOWN_TRFR_ID   = 5,
  TFTP_ERROR_FILE_EXISTS       = 6,
  TFTP_ERROR_NO_SUCH_USER      = 7
};

#include <string.h>

struct tftp_state {
  const struct tftp_context *ctx;
  void *handle;
  struct pbuf *last_data;
  struct udp_pcb *upcb;
  ip_addr_t addr;
  u16_t port;
  int timer;
  int last_pkt;
  u16_t blknum;
  u16_t blksize;          /* Requested block size (RFC 2348), 0 = use default */
  u16_t blksize_negotiated; /* Negotiated block size from OACK, 0 = not negotiated */
  u8_t retries;
  u8_t mode_write;
  u8_t tftp_mode;
};

static struct tftp_state tftp_state;

/* Configured blksize - persists even when TFTP client is not initialized */
static u16_t tftp_configured_blksize = 0;

static void tftp_tmr(void *arg);

static void
close_handle(void)
{
  tftp_state.port = 0;
  ip_addr_set_any(0, &tftp_state.addr);

  if (tftp_state.last_data != NULL) {
    pbuf_free(tftp_state.last_data);
    tftp_state.last_data = NULL;
  }

  sys_untimeout(tftp_tmr, NULL);

  if (tftp_state.handle) {
    tftp_state.ctx->close(tftp_state.handle);
    tftp_state.handle = NULL;
    LWIP_DEBUGF(TFTP_DEBUG | LWIP_DBG_STATE, ("tftp: closing\n"));
  }
}

static struct pbuf*
init_packet(u16_t opcode, u16_t extra, size_t size)
{
  struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)(TFTP_HEADER_LENGTH + size), PBUF_RAM);
  u16_t* payload;

  if (p != NULL) {
    payload = (u16_t*) p->payload;
    payload[0] = PP_HTONS(opcode);
    payload[1] = lwip_htons(extra);
  }

  return p;
}

static err_t
send_request(const ip_addr_t *addr, u16_t port, u16_t opcode, const char* fname, const char* mode)
{
  size_t fname_length = strlen(fname)+1;
  size_t mode_length = strlen(mode)+1;
  size_t total_size = fname_length + mode_length - 2;
  char blksize_str[8];
  size_t blksize_opt_length = 0;
  struct pbuf* p;
  char* payload;
  err_t ret;

  /* Add blksize option if configured (RFC 2348) */
  if (tftp_state.blksize != 0) {
    snprintf(blksize_str, sizeof(blksize_str), "%u", tftp_state.blksize);
    blksize_opt_length = 8 + strlen(blksize_str) + 1; /* "blksize\0" + value + "\0" */
    total_size += blksize_opt_length;
  }

  p = init_packet(opcode, 0, total_size);
  if (p == NULL) {
    return ERR_MEM;
  }

  payload = (char*) p->payload;
  MEMCPY(payload+2,              fname, fname_length);
  MEMCPY(payload+2+fname_length, mode,  mode_length);

  /* Append blksize option if configured */
  if (tftp_state.blksize != 0) {
    size_t offset = 2 + fname_length + mode_length;
    MEMCPY(payload+offset, "blksize", 8); /* includes \0 */
    MEMCPY(payload+offset+8, blksize_str, strlen(blksize_str)+1);
  }

  ret = udp_sendto(tftp_state.upcb, p, addr, port);
  pbuf_free(p);
  return ret;
}

static err_t
send_error(const ip_addr_t *addr, u16_t port, enum tftp_error code, const char *str)
{
  size_t str_length = strlen(str);
  struct pbuf *p;
  u16_t *payload;
  err_t ret;

  p = init_packet(TFTP_ERROR, code, str_length + 1);
  if (p == NULL) {
    return ERR_MEM;
  }

  payload = (u16_t *) p->payload;
  MEMCPY(&payload[2], str, str_length + 1);

  ret = udp_sendto(tftp_state.upcb, p, addr, port);
  pbuf_free(p);
  return ret;
}

static err_t
send_ack(const ip_addr_t *addr, u16_t port, u16_t blknum)
{
  struct pbuf *p;
  err_t ret;

  p = init_packet(TFTP_ACK, blknum, 0);
  if (p == NULL) {
    return ERR_MEM;
  }

  ret = udp_sendto(tftp_state.upcb, p, addr, port);
  pbuf_free(p);
  return ret;
}

static err_t
resend_data(const ip_addr_t *addr, u16_t port)
{
  err_t ret;
  struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, tftp_state.last_data->len, PBUF_RAM);
  if (p == NULL) {
    return ERR_MEM;
  }

  ret = pbuf_copy(p, tftp_state.last_data);
  if (ret != ERR_OK) {
    pbuf_free(p);
    return ret;
  }

  ret = udp_sendto(tftp_state.upcb, p, addr, port);
  pbuf_free(p);
  return ret;
}

static void
send_data(const ip_addr_t *addr, u16_t port)
{
  u16_t *payload;
  int ret;
  u16_t blksize;

  if (tftp_state.last_data != NULL) {
    pbuf_free(tftp_state.last_data);
  }

  /* Use negotiated blksize if available, otherwise use default */
  blksize = (tftp_state.blksize_negotiated != 0) ? tftp_state.blksize_negotiated : TFTP_MAX_PAYLOAD_SIZE;

  tftp_state.last_data = init_packet(TFTP_DATA, tftp_state.blknum, blksize);
  if (tftp_state.last_data == NULL) {
    return;
  }

  payload = (u16_t *) tftp_state.last_data->payload;

  ret = tftp_state.ctx->read(tftp_state.handle, &payload[2], blksize);
  if (ret < 0) {
    send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Error occurred while reading the file.");
    close_handle();
    return;
  }

  pbuf_realloc(tftp_state.last_data, (u16_t)(TFTP_HEADER_LENGTH + ret));
  resend_data(addr, port);
}

static void
tftp_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  u16_t *sbuf = (u16_t *) p->payload;
  int opcode;

  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(upcb);

  fprintf(stderr, "DEBUG: tftp_recv: port=%u, tftp_state.port=%u\n", port, tftp_state.port);

  if (((tftp_state.port != 0) && (port != tftp_state.port)) ||
      (!ip_addr_isany_val(tftp_state.addr) && !ip_addr_eq(&tftp_state.addr, addr))) {
    fprintf(stderr, "DEBUG: tftp_recv: Connection check failed, sending error\n");
    send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Only one connection at a time is supported");
    pbuf_free(p);
    return;
  }

  opcode = sbuf[0];
  fprintf(stderr, "DEBUG: tftp_recv: opcode=0x%04x (TFTP_OACK=0x%04x)\n", opcode, PP_HTONS(TFTP_OACK));

  tftp_state.last_pkt = tftp_state.timer;
  tftp_state.retries = 0;

  switch (opcode) {
    case PP_HTONS(TFTP_RRQ): /* fall through */
    case PP_HTONS(TFTP_WRQ): {
      const char tftp_null = 0;
      char filename[TFTP_MAX_FILENAME_LEN + 1];
      char mode[TFTP_MAX_MODE_LEN + 1];
      u16_t filename_end_offset;
      u16_t mode_end_offset;

      if (tftp_state.handle != NULL) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Only one connection at a time is supported");
        break;
      }

      if ((tftp_state.tftp_mode & LWIP_TFTP_MODE_SERVER) == 0) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "TFTP server not enabled");
        break;
      }

      sys_timeout(TFTP_TIMER_MSECS, tftp_tmr, NULL);

      /* find \0 in pbuf -> end of filename string */
      filename_end_offset = pbuf_memfind(p, &tftp_null, sizeof(tftp_null), 2);
      if ((u16_t)(filename_end_offset - 1) > sizeof(filename)) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Filename too long/not NULL terminated");
        break;
      }
      pbuf_copy_partial(p, filename, filename_end_offset - 1, 2);

      /* find \0 in pbuf -> end of mode string */
      mode_end_offset = pbuf_memfind(p, &tftp_null, sizeof(tftp_null), filename_end_offset + 1);
      if ((u16_t)(mode_end_offset - filename_end_offset) > sizeof(mode)) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Mode too long/not NULL terminated");
        break;
      }
      pbuf_copy_partial(p, mode, mode_end_offset - filename_end_offset, filename_end_offset + 1);

      tftp_state.handle = tftp_state.ctx->open(filename, mode, opcode == PP_HTONS(TFTP_WRQ));
      tftp_state.blknum = 1;

      if (!tftp_state.handle) {
        send_error(addr, port, TFTP_ERROR_FILE_NOT_FOUND, "Unable to open requested file.");
        break;
      }

      LWIP_DEBUGF(TFTP_DEBUG | LWIP_DBG_STATE, ("tftp: %s request from ", (opcode == PP_HTONS(TFTP_WRQ)) ? "write" : "read"));
      ip_addr_debug_print(TFTP_DEBUG | LWIP_DBG_STATE, addr);
      LWIP_DEBUGF(TFTP_DEBUG | LWIP_DBG_STATE, (" for '%s' mode '%s'\n", filename, mode));

      ip_addr_copy(tftp_state.addr, *addr);
      tftp_state.port = port;

      if (opcode == PP_HTONS(TFTP_WRQ)) {
        tftp_state.mode_write = 1;
        send_ack(addr, port, 0);
      } else {
        tftp_state.mode_write = 0;
        send_data(addr, port);
      }

      break;
    }

    case PP_HTONS(TFTP_DATA): {
      int ret;
      u16_t blknum;
      u16_t expected_blksize;

      if (tftp_state.handle == NULL) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "No connection");
        break;
      }

      if (tftp_state.mode_write != 1) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Not a write connection");
        break;
      }

      blknum = lwip_ntohs(sbuf[1]);
      if (blknum == tftp_state.blknum) {
        /* If this is the first DATA packet (block 1) in client mode, update connection info */
        if (blknum == 1 && tftp_state.port == 0) {
          ip_addr_copy(tftp_state.addr, *addr);
          tftp_state.port = port;
        }

        pbuf_remove_header(p, TFTP_HEADER_LENGTH);

        ret = tftp_state.ctx->write(tftp_state.handle, p);
        if (ret < 0) {
          send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "error writing file");
          close_handle();
        } else {
          send_ack(addr, port, blknum);
        }

        /* Determine expected blocksize - use negotiated or default */
        expected_blksize = (tftp_state.blksize_negotiated != 0) ? tftp_state.blksize_negotiated : TFTP_MAX_PAYLOAD_SIZE;

        /* Check if this is the final block (smaller than expected blocksize) */
        if (p->tot_len < expected_blksize) {
          close_handle();
        } else {
          tftp_state.blknum++;
        }
      } else if ((u16_t)(blknum + 1) == tftp_state.blknum) {
        /* retransmit of previous block, ack again (casting to u16_t to care for overflow) */
        send_ack(addr, port, blknum);
      } else {
        send_error(addr, port, TFTP_ERROR_UNKNOWN_TRFR_ID, "Wrong block number");
      }
      break;
    }

    case PP_HTONS(TFTP_ACK): {
      u16_t blknum;
      int lastpkt;
      u16_t expected_blksize;

      if (tftp_state.handle == NULL) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "No connection");
        break;
      }

      if (tftp_state.mode_write != 0) {
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "Not a read connection");
        break;
      }

      blknum = lwip_ntohs(sbuf[1]);
      if (blknum != tftp_state.blknum) {
        send_error(addr, port, TFTP_ERROR_UNKNOWN_TRFR_ID, "Wrong block number");
        break;
      }

      /* If this is the first ACK (block 0) in client mode, update connection info */
      if (blknum == 0 && tftp_state.port == 0) {
        ip_addr_copy(tftp_state.addr, *addr);
        tftp_state.port = port;
      }

      lastpkt = 0;

      /* Determine expected blocksize - use negotiated or default */
      expected_blksize = (tftp_state.blksize_negotiated != 0) ? tftp_state.blksize_negotiated : TFTP_MAX_PAYLOAD_SIZE;

      if (tftp_state.last_data != NULL) {
        lastpkt = tftp_state.last_data->tot_len != (expected_blksize + TFTP_HEADER_LENGTH);
      }

      if (!lastpkt) {
        tftp_state.blknum++;
        send_data(addr, port);
      } else {
        close_handle();
      }

      break;
    }
    case PP_HTONS(TFTP_OACK): {
      /* Option Acknowledgement (RFC 2348) */
      const char tftp_null = 0;
      u16_t offset;
      u16_t opt_end_offset;
      char option_name[16];
      char option_value[16];
      u16_t negotiated_blksize = 0;

      fprintf(stderr, "DEBUG: tftp_recv: OACK received, blksize=%u\n", tftp_state.blksize);

      if (tftp_state.handle == NULL) {
        fprintf(stderr, "DEBUG: tftp_recv: OACK rejected - no connection\n");
        send_error(addr, port, TFTP_ERROR_ACCESS_VIOLATION, "No connection");
        break;
      }

      /* Only process OACK if we requested options */
      if (tftp_state.blksize == 0) {
        fprintf(stderr, "DEBUG: tftp_recv: OACK rejected - no options requested (blksize=0)\n");
        send_error(addr, port, TFTP_ERROR_ILLEGAL_OPERATION, "Unexpected OACK");
        close_handle();
        break;
      }

      /* Parse options in OACK */
      offset = 2; /* Skip opcode */
      while (offset < p->tot_len) {
        /* Find end of option name */
        opt_end_offset = pbuf_memfind(p, &tftp_null, sizeof(tftp_null), offset);
        if (opt_end_offset == 0xFFFF || (u16_t)(opt_end_offset - offset) >= sizeof(option_name)) {
          break;
        }
        pbuf_copy_partial(p, option_name, opt_end_offset - offset, offset);
        option_name[opt_end_offset - offset] = '\0';
        offset = opt_end_offset + 1;

        /* Find end of option value */
        if (offset >= p->tot_len) {
          break;
        }
        opt_end_offset = pbuf_memfind(p, &tftp_null, sizeof(tftp_null), offset);
        if (opt_end_offset == 0xFFFF || (u16_t)(opt_end_offset - offset) >= sizeof(option_value)) {
          break;
        }
        pbuf_copy_partial(p, option_value, opt_end_offset - offset, offset);
        option_value[opt_end_offset - offset] = '\0';
        offset = opt_end_offset + 1;

        fprintf(stderr, "DEBUG: tftp_recv: OACK option: %s = %s\n", option_name, option_value);

        /* Check if this is the blksize option */
        if (strcasecmp(option_name, "blksize") == 0) {
          negotiated_blksize = (u16_t)atoi(option_value);
        }
      }

      fprintf(stderr, "DEBUG: tftp_recv: negotiated_blksize=%u, requested=%u\n", negotiated_blksize, tftp_state.blksize);

      /* Validate negotiated blksize */
      if (negotiated_blksize < TFTP_BLKSIZE_MIN || negotiated_blksize > tftp_state.blksize) {
        fprintf(stderr, "DEBUG: tftp_recv: OACK rejected - invalid blksize\n");
        send_error(addr, port, TFTP_ERROR_ILLEGAL_OPERATION, "Invalid blksize in OACK");
        close_handle();
        break;
      }

      /* Accept the negotiated blksize */
      tftp_state.blksize_negotiated = negotiated_blksize;
      fprintf(stderr, "DEBUG: tftp_recv: Accepted blksize_negotiated=%u\n", tftp_state.blksize_negotiated);

      /* Update connection info */
      ip_addr_copy(tftp_state.addr, *addr);
      tftp_state.port = port;

      /* Send ACK for block 0 to acknowledge OACK */
      fprintf(stderr, "DEBUG: tftp_recv: Sending ACK 0 for OACK\n");
      send_ack(addr, port, 0);

      /* For write mode, send first data block after OACK */
      if (tftp_state.mode_write == 0) {
        fprintf(stderr, "DEBUG: tftp_recv: WRQ mode, sending first DATA block\n");
        tftp_state.blknum = 1;
        send_data(addr, port);
      }

      break;
    }

    case PP_HTONS(TFTP_ERROR):
      if (tftp_state.handle != NULL) {
        pbuf_remove_header(p, TFTP_HEADER_LENGTH);
        tftp_state.ctx->error(tftp_state.handle, sbuf[1], (const char*)p->payload, p->len);
        close_handle();
      }
      break;
    default:
      send_error(addr, port, TFTP_ERROR_ILLEGAL_OPERATION, "Unknown operation");
      break;
  }

  pbuf_free(p);
}

static void
tftp_tmr(void *arg)
{
  LWIP_UNUSED_ARG(arg);

  tftp_state.timer++;

  if (tftp_state.handle == NULL) {
    return;
  }

  sys_timeout(TFTP_TIMER_MSECS, tftp_tmr, NULL);

  if ((tftp_state.timer - tftp_state.last_pkt) > (TFTP_TIMEOUT_MSECS / TFTP_TIMER_MSECS)) {
    if ((tftp_state.last_data != NULL) && (tftp_state.retries < TFTP_MAX_RETRIES)) {
      LWIP_DEBUGF(TFTP_DEBUG | LWIP_DBG_STATE, ("tftp: timeout, retrying\n"));
      resend_data(&tftp_state.addr, tftp_state.port);
      tftp_state.retries++;
    } else {
      LWIP_DEBUGF(TFTP_DEBUG | LWIP_DBG_STATE, ("tftp: timeout\n"));
      close_handle();
    }
  }
}

/**
 * Initialize TFTP client/server.
 * @param mode TFTP mode (client/server)
 * @param ctx TFTP callback struct
 */
err_t
tftp_init_common(u8_t mode, const struct tftp_context *ctx)
{
  err_t ret;

  /* LWIP_ASSERT_CORE_LOCKED(); is checked by udp_new() */
  struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
  if (pcb == NULL) {
    return ERR_MEM;
  }

  if (mode & LWIP_TFTP_MODE_SERVER) {
    ret = udp_bind(pcb, IP_ANY_TYPE, TFTP_PORT);
    if (ret != ERR_OK) {
      udp_remove(pcb);
      return ret;
    }
  }

  tftp_state.handle    = NULL;
  tftp_state.port      = 0;
  tftp_state.ctx       = ctx;
  tftp_state.timer     = 0;
  tftp_state.last_data = NULL;
  tftp_state.upcb      = pcb;
  tftp_state.tftp_mode = mode;
  tftp_state.blksize   = 0;
  tftp_state.blksize_negotiated = 0;
  ip_addr_set_any(0, &tftp_state.addr);

  udp_recv(pcb, tftp_recv, NULL);

  return ERR_OK;
}

/** @ingroup tftp
 * Initialize TFTP server.
 * @param ctx TFTP callback struct
 */
err_t
tftp_init_server(const struct tftp_context *ctx)
{
  return tftp_init_common(LWIP_TFTP_MODE_SERVER, ctx);
}

/** @ingroup tftp
 * Initialize TFTP client.
 * @param ctx TFTP callback struct
 */
err_t
tftp_init_client(const struct tftp_context *ctx)
{
  return tftp_init_common(LWIP_TFTP_MODE_CLIENT, ctx);
}

/** @ingroup tftp
 * Deinitialize ("turn off") TFTP client/server.
 */
void tftp_cleanup(void)
{
  LWIP_ASSERT("Cleanup called on non-initialized TFTP", tftp_state.upcb != NULL);
  udp_remove(tftp_state.upcb);
  close_handle();
  memset(&tftp_state, 0, sizeof(tftp_state));
}

static const char *
mode_to_string(enum tftp_transfer_mode mode)
{
  if (mode == TFTP_MODE_OCTET) {
    return "octet";
  }
  if (mode == TFTP_MODE_NETASCII) {
    return "netascii";
  }
  if (mode == TFTP_MODE_BINARY) {
    return "binary";
  }
  return NULL;
}

err_t
tftp_get(void* handle, const ip_addr_t *addr, u16_t port, const char* fname, enum tftp_transfer_mode mode)
{
  LWIP_ERROR("TFTP client is not enabled (tftp_init)", (tftp_state.tftp_mode & LWIP_TFTP_MODE_CLIENT) != 0, return ERR_VAL);
  LWIP_ERROR("tftp_get: invalid file name", fname != NULL, return ERR_VAL);
  LWIP_ERROR("tftp_get: invalid mode", mode <= TFTP_MODE_BINARY, return ERR_VAL);

  tftp_state.handle = handle;
  tftp_state.blknum = 1;
  tftp_state.mode_write = 1; /* We want to receive data */
  sys_timeout(TFTP_TIMER_MSECS, tftp_tmr, NULL);
  return send_request(addr, port, TFTP_RRQ, fname, mode_to_string(mode));
}

err_t
tftp_put(void* handle, const ip_addr_t *addr, u16_t port, const char* fname, enum tftp_transfer_mode mode)
{
  LWIP_ERROR("TFTP client is not enabled (tftp_init)", (tftp_state.tftp_mode & LWIP_TFTP_MODE_CLIENT) != 0, return ERR_VAL);
  LWIP_ERROR("tftp_put: invalid file name", fname != NULL, return ERR_VAL);
  LWIP_ERROR("tftp_put: invalid mode", mode <= TFTP_MODE_BINARY, return ERR_VAL);

  tftp_state.handle = handle;
  tftp_state.blknum = 0; /* For WRQ, we expect ACK 0 first */
  tftp_state.mode_write = 0; /* We want to send data */
  sys_timeout(TFTP_TIMER_MSECS, tftp_tmr, NULL);
  return send_request(addr, port, TFTP_WRQ, fname, mode_to_string(mode));
}

/** @ingroup tftp
 * Set the block size for TFTP transfers (RFC 2348).
 * Must be called after tftp_init_client() and before tftp_get()/tftp_put().
 * @param blksize Desired block size (8-65464 bytes)
 * @return ERR_OK on success
 */
err_t
tftp_client_set_blksize(u16_t blksize)
{
  /* Validate blksize range per RFC 2348 */
  if (blksize < TFTP_BLKSIZE_MIN || blksize > TFTP_BLKSIZE_MAX) {
    return ERR_VAL;
  }

  /* Always save to configured blksize */
  tftp_configured_blksize = blksize;

  /* Also update tftp_state if initialized and no transfer in progress */
  if (tftp_state.upcb != NULL && tftp_state.handle == NULL) {
    tftp_state.blksize = blksize;
  }

  return ERR_OK;
}

/** @ingroup tftp
 * Get the current TFTP block size setting.
 * @return Current block size in bytes (default 512 if not configured)
 */
u16_t
tftp_client_get_blksize(void)
{
  /* Return configured blksize if set */
  if (tftp_configured_blksize != 0) {
    return tftp_configured_blksize;
  }
  /* Fall back to tftp_state.blksize if set */
  if (tftp_state.blksize != 0) {
    return tftp_state.blksize;
  }
  return TFTP_MAX_PAYLOAD_SIZE;
}

#endif /* LWIP_UDP */
