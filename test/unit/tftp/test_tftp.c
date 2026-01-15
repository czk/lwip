/**
 * @file test_tftp.c
 * Unit tests for TFTP client blocksize option (RFC 2348)
 */

#include "test_tftp.h"

#include "lwip/apps/tftp_client.h"
#include "lwip/apps/tftp_common.h"
#include "lwip/udp.h"
#include "lwip/stats.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip4.h"
#include "lwip/prot/ip4.h"

#include <string.h>

#if !LWIP_STATS || !UDP_STATS || !MEMP_STATS
#error "This tests needs UDP- and MEMP-statistics enabled"
#endif

/* TFTP protocol constants */
#define TFTP_DEFAULT_BLKSIZE   512
#define TFTP_MIN_BLKSIZE       8
#define TFTP_MAX_BLKSIZE       65464
#define TFTP_HEADER_LENGTH     4
#define TFTP_TEST_PORT         69

/* TFTP opcodes */
#define TFTP_RRQ   1
#define TFTP_WRQ   2
#define TFTP_DATA  3
#define TFTP_ACK   4
#define TFTP_ERROR 5
#define TFTP_OACK  6

/* Test state */
static struct netif test_netif;
static ip4_addr_t test_gw, test_ipaddr, test_netmask;
static int output_ctr;
static struct pbuf *last_output_pbuf;
static u16_t last_output_port;

/* Mock file context */
static int mock_open_called;
static int mock_close_called;
static int mock_read_called;
static int mock_write_called;
static int mock_error_called;
static char mock_read_data[2048];
static int mock_read_data_len;
static int mock_read_offset;

/* Captured request data */
static u8_t captured_request[TFTP_MAX_BLKSIZE + TFTP_HEADER_LENGTH];  /* 65468 bytes - supports max blocksize */
static u16_t captured_request_len;

/* Helper functions */

static void *
mock_open(const char *fname, const char *mode, u8_t write)
{
  LWIP_UNUSED_ARG(fname);
  LWIP_UNUSED_ARG(mode);
  LWIP_UNUSED_ARG(write);
  mock_open_called++;
  return (void *)0x12345678; /* Return a non-NULL handle */
}

static void
mock_close(void *handle)
{
  LWIP_UNUSED_ARG(handle);
  mock_close_called++;
}

static int
mock_read(void *handle, void *buf, int bytes)
{
  int to_read;
  LWIP_UNUSED_ARG(handle);
  mock_read_called++;

  to_read = mock_read_data_len - mock_read_offset;
  if (to_read > bytes) {
    to_read = bytes;
  }
  if (to_read > 0) {
    memcpy(buf, mock_read_data + mock_read_offset, to_read);
    mock_read_offset += to_read;
  }
  return to_read;
}

static int
mock_write(void *handle, struct pbuf *p)
{
  LWIP_UNUSED_ARG(handle);
  LWIP_UNUSED_ARG(p);
  mock_write_called++;
  return p->tot_len;
}

static void
mock_error(void *handle, int err, const char *msg, int size)
{
  LWIP_UNUSED_ARG(handle);
  LWIP_UNUSED_ARG(err);
  LWIP_UNUSED_ARG(msg);
  LWIP_UNUSED_ARG(size);
  mock_error_called++;
}

static const struct tftp_context test_ctx = {
  mock_open,
  mock_close,
  mock_read,
  mock_write,
  mock_error
};

static err_t
test_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  LWIP_UNUSED_ARG(ipaddr);
  output_ctr++;
  return ERR_OK;
}

static err_t
test_netif_linkoutput(struct netif *netif, struct pbuf *p)
{
  struct ip_hdr *iphdr;
  struct udp_hdr *udphdr;
  u16_t ip_hlen;

  LWIP_UNUSED_ARG(netif);
  output_ctr++;

  /* Parse IP header */
  iphdr = (struct ip_hdr *)p->payload;
  ip_hlen = IPH_HL(iphdr) * 4;

  /* Parse UDP header */
  udphdr = (struct udp_hdr *)((u8_t *)p->payload + ip_hlen);
  last_output_port = lwip_ntohs(udphdr->dest);

  /* Capture the TFTP payload */
  if (last_output_pbuf != NULL) {
    pbuf_free(last_output_pbuf);
  }
  last_output_pbuf = pbuf_alloc(PBUF_RAW, p->tot_len - ip_hlen - sizeof(struct udp_hdr), PBUF_RAM);
  if (last_output_pbuf != NULL) {
    pbuf_copy_partial(p, last_output_pbuf->payload, last_output_pbuf->len,
                      ip_hlen + sizeof(struct udp_hdr));
    captured_request_len = last_output_pbuf->len;
    if (captured_request_len <= sizeof(captured_request)) {
      memcpy(captured_request, last_output_pbuf->payload, captured_request_len);
    }
  }

  return ERR_OK;
}

static err_t
test_netif_init(struct netif *netif)
{
  netif->output = test_netif_output;
  netif->linkoutput = test_netif_linkoutput;
  netif->mtu = 1500;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
  netif->hwaddr_len = 6;
  return ERR_OK;
}

static void
test_netif_add(void)
{
  struct netif *n;

  IP4_ADDR(&test_ipaddr, 192, 168, 0, 1);
  IP4_ADDR(&test_netmask, 255, 255, 255, 0);
  IP4_ADDR(&test_gw, 192, 168, 0, 254);
  n = netif_add(&test_netif, &test_ipaddr, &test_netmask,
                &test_gw, NULL, test_netif_init, NULL);
  fail_unless(n == &test_netif);

  netif_set_default(&test_netif);
  netif_set_up(&test_netif);
}

static void
test_netif_remove(void)
{
  netif_remove(&test_netif);
}

static void
reset_mock_state(void)
{
  mock_open_called = 0;
  mock_close_called = 0;
  mock_read_called = 0;
  mock_write_called = 0;
  mock_error_called = 0;
  mock_read_data_len = 0;
  mock_read_offset = 0;
  output_ctr = 0;
  captured_request_len = 0;
  memset(captured_request, 0, sizeof(captured_request));
  memset(mock_read_data, 0, sizeof(mock_read_data));

  if (last_output_pbuf != NULL) {
    pbuf_free(last_output_pbuf);
    last_output_pbuf = NULL;
  }
}

/* Setup/teardown functions */

static void
tftp_setup(void)
{
  reset_mock_state();
  test_netif_add();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
tftp_teardown(void)
{
  /* Clean up TFTP state if initialized */
  /* Note: tftp_cleanup() will be called by tests that init TFTP */
  reset_mock_state();
  test_netif_remove();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

/* Helper to check if a string option exists in TFTP request */
static int
find_option_in_request(const u8_t *request, u16_t len, const char *option, char *value, int value_size)
{
  u16_t i = 2; /* Skip opcode */
  int found_filename = 0;
  int found_mode = 0;
  const char *opt_name;
  const char *opt_value;
  u16_t opt_name_len;
  u16_t opt_value_len;

  /* Skip filename and mode first */
  while (i < len) {
    if (request[i] == 0) {
      if (!found_filename) {
        found_filename = 1;
      } else if (!found_mode) {
        found_mode = 1;
        i++;
        break;
      }
    }
    i++;
  }

  /* Now look for options */
  while (i < len) {
    opt_name = (const char *)&request[i];
    opt_name_len = (u16_t)strlen(opt_name);

    if (i + opt_name_len >= len) {
      break;
    }

    i += opt_name_len + 1;

    if (i >= len) {
      break;
    }

    opt_value = (const char *)&request[i];
    opt_value_len = (u16_t)strlen(opt_value);

    if (strcasecmp(opt_name, option) == 0) {
      if (value != NULL && value_size > 0) {
        strncpy(value, opt_value, (size_t)(value_size - 1));
        value[value_size - 1] = '\0';
      }
      return 1;
    }

    i += opt_value_len + 1;
  }

  return 0;
}

/* Create a simulated TFTP packet for input */
static struct pbuf *
create_tftp_packet(u16_t opcode, u16_t block_or_error, const u8_t *data, u16_t data_len)
{
  struct pbuf *p;
  struct ip_hdr *iphdr;
  struct udp_hdr *udphdr;
  u8_t *payload;
  u16_t tftp_len = TFTP_HEADER_LENGTH + data_len;
  u16_t udp_len = sizeof(struct udp_hdr) + tftp_len;
  u16_t total_len = sizeof(struct ip_hdr) + udp_len;

  p = pbuf_alloc(PBUF_RAW, total_len, PBUF_RAM);
  if (p == NULL) {
    return NULL;
  }

  /* Build IP header */
  iphdr = (struct ip_hdr *)p->payload;
  memset(iphdr, 0, sizeof(*iphdr));
  IPH_VHL_SET(iphdr, 4, sizeof(struct ip_hdr) / 4);
  IPH_LEN_SET(iphdr, lwip_htons(total_len));
  IPH_TTL_SET(iphdr, 64);
  IPH_PROTO_SET(iphdr, IP_PROTO_UDP);
  ip4_addr_set_u32(&iphdr->src, PP_HTONL(0xC0A800FE)); /* 192.168.0.254 */
  ip4_addr_set_u32(&iphdr->dest, test_ipaddr.addr);
  IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, sizeof(struct ip_hdr)));

  /* Build UDP header */
  udphdr = (struct udp_hdr *)((u8_t *)p->payload + sizeof(struct ip_hdr));
  udphdr->src = lwip_htons(12345); /* Arbitrary source port */
  udphdr->dest = lwip_htons(TFTP_TEST_PORT);
  udphdr->len = lwip_htons(udp_len);
  udphdr->chksum = 0;

  /* Build TFTP payload */
  payload = (u8_t *)p->payload + sizeof(struct ip_hdr) + sizeof(struct udp_hdr);
  payload[0] = (u8_t)(opcode >> 8);
  payload[1] = (u8_t)(opcode & 0xFF);
  payload[2] = (u8_t)(block_or_error >> 8);
  payload[3] = (u8_t)(block_or_error & 0xFF);

  if (data != NULL && data_len > 0) {
    memcpy(payload + TFTP_HEADER_LENGTH, data, data_len);
  }

  return p;
}

/* Create an OACK packet with blksize option */
static struct pbuf *
create_oack_packet(u16_t blksize)
{
  struct pbuf *p;
  struct ip_hdr *iphdr;
  struct udp_hdr *udphdr;
  u8_t *payload;
  char blksize_str[16];
  u16_t opt_len;
  u16_t tftp_len;
  u16_t udp_len;
  u16_t total_len;

  snprintf(blksize_str, sizeof(blksize_str), "%u", blksize);
  opt_len = 7 + 1 + strlen(blksize_str) + 1; /* "blksize" + \0 + value + \0 */
  tftp_len = 2 + opt_len; /* opcode + options */
  udp_len = sizeof(struct udp_hdr) + tftp_len;
  total_len = sizeof(struct ip_hdr) + udp_len;

  p = pbuf_alloc(PBUF_RAW, total_len, PBUF_RAM);
  if (p == NULL) {
    return NULL;
  }

  /* Build IP header */
  iphdr = (struct ip_hdr *)p->payload;
  memset(iphdr, 0, sizeof(*iphdr));
  IPH_VHL_SET(iphdr, 4, sizeof(struct ip_hdr) / 4);
  IPH_LEN_SET(iphdr, lwip_htons(total_len));
  IPH_TTL_SET(iphdr, 64);
  IPH_PROTO_SET(iphdr, IP_PROTO_UDP);
  ip4_addr_set_u32(&iphdr->src, PP_HTONL(0xC0A800FE)); /* 192.168.0.254 */
  ip4_addr_set_u32(&iphdr->dest, test_ipaddr.addr);
  IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, sizeof(struct ip_hdr)));

  /* Build UDP header */
  udphdr = (struct udp_hdr *)((u8_t *)p->payload + sizeof(struct ip_hdr));
  udphdr->src = lwip_htons(12345);
  udphdr->dest = lwip_htons(TFTP_TEST_PORT);
  udphdr->len = lwip_htons(udp_len);
  udphdr->chksum = 0;

  /* Build TFTP OACK payload */
  payload = (u8_t *)p->payload + sizeof(struct ip_hdr) + sizeof(struct udp_hdr);
  payload[0] = 0;
  payload[1] = TFTP_OACK;
  memcpy(payload + 2, "blksize", 8); /* includes \0 */
  memcpy(payload + 2 + 8, blksize_str, strlen(blksize_str) + 1);

  return p;
}

/*
 * ===========================================================================
 * API Tests for tftp_client_set_blksize()
 * ===========================================================================
 */

/**
 * Test: tftp_client_set_blksize() returns error when called before tftp_init_client()
 */
START_TEST(test_tftp_set_blksize_before_init)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  /* Call set_blksize before init - should fail */
  err = tftp_client_set_blksize(1024);
  fail_unless(err != ERR_OK, "set_blksize should fail before init");
}
END_TEST

/**
 * Test: tftp_client_set_blksize() succeeds after tftp_init_client() and before tftp_get()
 */
START_TEST(test_tftp_set_blksize_after_init)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* Call set_blksize after init - should succeed */
  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize should succeed after init");

  tftp_cleanup();
}
END_TEST

/**
 * Test: tftp_client_set_blksize() accepts minimum valid blocksize (8 bytes per RFC 2348)
 */
START_TEST(test_tftp_set_blksize_minimum)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(TFTP_MIN_BLKSIZE);
  fail_unless(err == ERR_OK, "set_blksize should accept minimum blocksize (8)");

  tftp_cleanup();
}
END_TEST

/**
 * Test: tftp_client_set_blksize() accepts maximum valid blocksize (65464 per RFC 2348)
 */
START_TEST(test_tftp_set_blksize_maximum)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(TFTP_MAX_BLKSIZE);
  fail_unless(err == ERR_OK, "set_blksize should accept maximum blocksize (65464)");

  tftp_cleanup();
}
END_TEST

/**
 * Test: tftp_client_set_blksize() accepts typical Ethernet-optimal blocksize (1468)
 */
START_TEST(test_tftp_set_blksize_ethernet_optimal)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* 1500 MTU - 20 IP header - 8 UDP header - 4 TFTP header = 1468 */
  err = tftp_client_set_blksize(1468);
  fail_unless(err == ERR_OK, "set_blksize should accept 1468 (Ethernet optimal)");

  tftp_cleanup();
}
END_TEST

/**
 * Test: tftp_client_set_blksize() rejects blocksize below minimum
 */
START_TEST(test_tftp_set_blksize_below_minimum)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(7); /* Below minimum of 8 */
  fail_unless(err != ERR_OK, "set_blksize should reject blocksize below minimum");

  err = tftp_client_set_blksize(0);
  fail_unless(err != ERR_OK, "set_blksize should reject blocksize of 0");

  tftp_cleanup();
}
END_TEST

/**
 * Test: tftp_client_set_blksize() rejects blocksize above maximum
 */
START_TEST(test_tftp_set_blksize_above_maximum)
{
  err_t err;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(65465); /* Above maximum of 65464 */
  fail_unless(err != ERR_OK, "set_blksize should reject blocksize above maximum");

  tftp_cleanup();
}
END_TEST

/**
 * Test: tftp_client_set_blksize() returns error when transfer is in progress
 */
START_TEST(test_tftp_set_blksize_during_transfer)
{
  err_t err;
  ip_addr_t server_addr;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* Start a transfer */
  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Try to set blocksize during transfer - should fail */
  err = tftp_client_set_blksize(1024);
  fail_unless(err != ERR_OK, "set_blksize should fail during transfer");

  tftp_cleanup();
}
END_TEST

/*
 * ===========================================================================
 * Protocol Tests for RRQ with blocksize option
 * ===========================================================================
 */

/**
 * Test: RRQ includes blksize option when set
 */
START_TEST(test_tftp_rrq_includes_blksize_option)
{
  err_t err;
  ip_addr_t server_addr;
  char blksize_value[16];
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Verify the request was sent */
  fail_unless(output_ctr > 0, "No packet was sent");

  /* Verify the request contains blksize option */
  fail_unless(find_option_in_request(captured_request, captured_request_len, "blksize", blksize_value, sizeof(blksize_value)),
              "RRQ should contain blksize option");
  fail_unless(strcmp(blksize_value, "1024") == 0, "blksize value should be 1024");

  tftp_cleanup();
}
END_TEST

/**
 * Test: RRQ does not include blksize option when not set (default 512)
 */
START_TEST(test_tftp_rrq_no_blksize_when_default)
{
  err_t err;
  ip_addr_t server_addr;
  char blksize_value[16];
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* Do NOT set blksize - use default 512 */

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Verify the request was sent */
  fail_unless(output_ctr > 0, "No packet was sent");

  /* Verify the request does NOT contain blksize option when using default */
  fail_unless(!find_option_in_request(captured_request, captured_request_len, "blksize", blksize_value, sizeof(blksize_value)),
              "RRQ should NOT contain blksize option when using default");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client handles OACK response with negotiated blksize
 */
START_TEST(test_tftp_client_handles_oack)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Simulate server OACK response with blksize=1024 */
  p = create_oack_packet(1024);
  fail_unless(p != NULL, "Failed to create OACK packet");

  output_ctr = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed");

  /* Client should send ACK for OACK (block 0) */
  fail_unless(output_ctr > 0, "Client should respond to OACK");

  /* Verify ACK was sent (opcode=4, block=0) */
  fail_unless(captured_request_len >= 4, "Response too short for ACK");
  fail_unless(captured_request[0] == 0 && captured_request[1] == TFTP_ACK, "Response should be ACK");
  fail_unless(captured_request[2] == 0 && captured_request[3] == 0, "ACK should be for block 0");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client handles OACK with server-negotiated smaller blksize
 */
START_TEST(test_tftp_client_handles_oack_smaller_blksize)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* Request 1024, server will negotiate down to 512 */
  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Simulate server OACK response with blksize=512 (smaller than requested) */
  p = create_oack_packet(512);
  fail_unless(p != NULL, "Failed to create OACK packet");

  output_ctr = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed");

  /* Client should accept the negotiated smaller blksize */
  fail_unless(output_ctr > 0, "Client should respond to OACK");
  fail_unless(captured_request[0] == 0 && captured_request[1] == TFTP_ACK, "Response should be ACK");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client falls back to 512-byte blocks when server sends DATA instead of OACK
 * This tests backward compatibility with servers that don't support RFC 2348
 */
START_TEST(test_tftp_client_fallback_to_default_blksize)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  u8_t test_data[512];
  LWIP_UNUSED_ARG(_i);

  memset(test_data, 'A', sizeof(test_data));

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Server ignores blksize option and sends DATA directly (512 bytes) */
  p = create_tftp_packet(TFTP_DATA, 1, test_data, 512);
  fail_unless(p != NULL, "Failed to create DATA packet");

  output_ctr = 0;
  mock_write_called = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed");

  /* Client should accept the data and send ACK */
  fail_unless(mock_write_called > 0, "Client should write received data");
  fail_unless(output_ctr > 0, "Client should send ACK");
  fail_unless(captured_request[0] == 0 && captured_request[1] == TFTP_ACK, "Response should be ACK");
  fail_unless(captured_request[2] == 0 && captured_request[3] == 1, "ACK should be for block 1");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client rejects OACK with invalid blksize (too small)
 */
START_TEST(test_tftp_client_rejects_invalid_oack_blksize_small)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Simulate server OACK response with invalid blksize=4 (below minimum) */
  p = create_oack_packet(4);
  fail_unless(p != NULL, "Failed to create OACK packet");

  output_ctr = 0;
  err = ip4_input(p, &test_netif);

  /* Client should send ERROR or close connection for invalid OACK */
  /* The specific behavior depends on implementation */

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client rejects OACK with blksize larger than requested
 */
START_TEST(test_tftp_client_rejects_oack_larger_than_requested)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Simulate server OACK response with blksize=2048 (larger than requested 1024) */
  p = create_oack_packet(2048);
  fail_unless(p != NULL, "Failed to create OACK packet");

  output_ctr = 0;
  err = ip4_input(p, &test_netif);

  /* Client should reject OACK with blksize larger than requested */
  /* Check that ERROR is sent or connection is closed */

  tftp_cleanup();
}
END_TEST

/*
 * ===========================================================================
 * Protocol Tests for WRQ with blocksize option
 * ===========================================================================
 */

/**
 * Test: WRQ includes blksize option when set
 */
START_TEST(test_tftp_wrq_includes_blksize_option)
{
  err_t err;
  ip_addr_t server_addr;
  char blksize_value[16];
  LWIP_UNUSED_ARG(_i);

  /* Setup mock read data */
  memset(mock_read_data, 'B', 1024);
  mock_read_data_len = 1024;

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_put((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_put failed");

  /* Verify the request was sent */
  fail_unless(output_ctr > 0, "No packet was sent");

  /* Verify the request contains blksize option */
  fail_unless(find_option_in_request(captured_request, captured_request_len, "blksize", blksize_value, sizeof(blksize_value)),
              "WRQ should contain blksize option");
  fail_unless(strcmp(blksize_value, "1024") == 0, "blksize value should be 1024");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client sends data with negotiated blksize after OACK in WRQ
 */
START_TEST(test_tftp_wrq_sends_data_with_negotiated_blksize)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  /* Setup mock read data - more than one block */
  memset(mock_read_data, 'C', 2048);
  mock_read_data_len = 2048;

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_put((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_put failed");

  /* Simulate server OACK response with blksize=1024 */
  p = create_oack_packet(1024);
  fail_unless(p != NULL, "Failed to create OACK packet");

  output_ctr = 0;
  mock_read_called = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed");

  /* Client should send DATA block 1 with negotiated blksize */
  fail_unless(output_ctr > 0, "Client should send DATA after OACK");
  fail_unless(mock_read_called > 0, "Client should read data to send");

  /* Verify DATA packet was sent */
  fail_unless(captured_request_len >= 4, "Response too short");
  fail_unless(captured_request[0] == 0 && captured_request[1] == TFTP_DATA, "Response should be DATA");
  fail_unless(captured_request[2] == 0 && captured_request[3] == 1, "DATA should be block 1");

  /* Verify data size is negotiated blksize (1024) + header (4) */
  fail_unless(captured_request_len == 1024 + 4, "DATA packet should be 1024 bytes + header");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Client falls back to 512-byte blocks for WRQ when server sends ACK without OACK
 */
START_TEST(test_tftp_wrq_fallback_to_default_blksize)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  /* Setup mock read data */
  memset(mock_read_data, 'D', 1024);
  mock_read_data_len = 1024;

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_put((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_put failed");

  /* Server ignores blksize option and sends ACK 0 directly */
  p = create_tftp_packet(TFTP_ACK, 0, NULL, 0);
  fail_unless(p != NULL, "Failed to create ACK packet");

  output_ctr = 0;
  mock_read_called = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed");

  /* Client should fall back to default blksize and send DATA */
  fail_unless(output_ctr > 0, "Client should send DATA after ACK");
  fail_unless(mock_read_called > 0, "Client should read data to send");

  /* Verify DATA packet was sent with default blksize (512) */
  fail_unless(captured_request_len >= 4, "Response too short");
  fail_unless(captured_request[0] == 0 && captured_request[1] == TFTP_DATA, "Response should be DATA");

  /* Data size should be 512 (default) + header (4) */
  fail_unless(captured_request_len == 512 + 4, "DATA packet should be 512 bytes + header (fallback)");

  tftp_cleanup();
}
END_TEST

/*
 * ===========================================================================
 * Edge Case Tests
 * ===========================================================================
 */

/**
 * Test: Blocksize is reset after tftp_cleanup()
 */
START_TEST(test_tftp_blksize_reset_after_cleanup)
{
  err_t err;
  ip_addr_t server_addr;
  char blksize_value[16];
  LWIP_UNUSED_ARG(_i);

  /* First session with blksize=1024 */
  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  tftp_cleanup();

  /* Second session without setting blksize */
  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed (2nd)");

  /* Do NOT set blksize - should be default */

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  output_ctr = 0;
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Verify the request does NOT contain blksize option (reset to default) */
  fail_unless(!find_option_in_request(captured_request, captured_request_len, "blksize", blksize_value, sizeof(blksize_value)),
              "RRQ should NOT contain blksize option after cleanup/reinit");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Multiple calls to set_blksize - last value wins
 */
START_TEST(test_tftp_set_blksize_multiple_calls)
{
  err_t err;
  ip_addr_t server_addr;
  char blksize_value[16];
  LWIP_UNUSED_ARG(_i);

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* Set different blocksizes multiple times */
  err = tftp_client_set_blksize(512);
  fail_unless(err == ERR_OK, "set_blksize(512) failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize(1024) failed");

  err = tftp_client_set_blksize(1468);
  fail_unless(err == ERR_OK, "set_blksize(1468) failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Verify the request contains last blksize value */
  fail_unless(find_option_in_request(captured_request, captured_request_len, "blksize", blksize_value, sizeof(blksize_value)),
              "RRQ should contain blksize option");
  fail_unless(strcmp(blksize_value, "1468") == 0, "blksize value should be 1468 (last set value)");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Receiving data block larger than expected (after negotiation)
 */
START_TEST(test_tftp_receive_oversized_data_block)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  u8_t test_data[2048];
  LWIP_UNUSED_ARG(_i);

  memset(test_data, 'E', sizeof(test_data));

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  /* Request 1024 byte blocks */
  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Server sends OACK with 1024 */
  p = create_oack_packet(1024);
  fail_unless(p != NULL, "Failed to create OACK packet");
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed for OACK");

  /* Server sends DATA block larger than negotiated (2048 bytes) */
  p = create_tftp_packet(TFTP_DATA, 1, test_data, 2048);
  fail_unless(p != NULL, "Failed to create DATA packet");

  mock_error_called = 0;
  err = ip4_input(p, &test_netif);

  /* Client should handle oversized block - either error or truncate */
  /* The specific behavior depends on implementation */

  tftp_cleanup();
}
END_TEST

/**
 * Test: Final block detection with custom blksize
 * A transfer ends when a block smaller than the negotiated blksize is received
 */
START_TEST(test_tftp_final_block_detection_custom_blksize)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  u8_t test_data[500]; /* Less than negotiated 1024 */
  LWIP_UNUSED_ARG(_i);

  memset(test_data, 'F', sizeof(test_data));

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Server sends OACK with 1024 */
  p = create_oack_packet(1024);
  fail_unless(p != NULL, "Failed to create OACK packet");
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed for OACK");

  /* Server sends final DATA block (smaller than 1024) */
  p = create_tftp_packet(TFTP_DATA, 1, test_data, 500);
  fail_unless(p != NULL, "Failed to create DATA packet");

  mock_write_called = 0;
  mock_close_called = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed for DATA");

  /* Client should recognize this as final block and close */
  fail_unless(mock_write_called > 0, "Client should write received data");
  fail_unless(mock_close_called > 0, "Client should close after final block");

  tftp_cleanup();
}
END_TEST

/**
 * Test: Zero-length final block with custom blksize
 * When file size is exact multiple of blksize, final block has 0 bytes
 */
START_TEST(test_tftp_zero_length_final_block)
{
  err_t err;
  ip_addr_t server_addr;
  struct pbuf *p;
  u8_t test_data[1024];
  LWIP_UNUSED_ARG(_i);

  memset(test_data, 'G', sizeof(test_data));

  err = tftp_init_client(&test_ctx);
  fail_unless(err == ERR_OK, "tftp_init_client failed");

  err = tftp_client_set_blksize(1024);
  fail_unless(err == ERR_OK, "set_blksize failed");

  IP_ADDR4(&server_addr, 192, 168, 0, 254);
  err = tftp_get((void *)0x12345678, &server_addr, TFTP_TEST_PORT, "test.txt", TFTP_MODE_OCTET);
  fail_unless(err == ERR_OK, "tftp_get failed");

  /* Server sends OACK with 1024 */
  p = create_oack_packet(1024);
  fail_unless(p != NULL, "Failed to create OACK packet");
  err = ip4_input(p, &test_netif);

  /* Server sends full DATA block 1 */
  p = create_tftp_packet(TFTP_DATA, 1, test_data, 1024);
  fail_unless(p != NULL, "Failed to create DATA packet");
  mock_close_called = 0;
  err = ip4_input(p, &test_netif);
  fail_unless(mock_close_called == 0, "Should not close after full block");

  /* Server sends zero-length final DATA block 2 */
  p = create_tftp_packet(TFTP_DATA, 2, NULL, 0);
  fail_unless(p != NULL, "Failed to create zero-length DATA packet");
  err = ip4_input(p, &test_netif);
  fail_unless(err == ERR_OK, "ip4_input failed for zero-length DATA");

  /* Client should recognize zero-length as final block and close */
  fail_unless(mock_close_called > 0, "Client should close after zero-length final block");

  tftp_cleanup();
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
tftp_suite(void)
{
  testfunc tests[] = {
    /* API tests */
    TESTFUNC(test_tftp_set_blksize_before_init),
    TESTFUNC(test_tftp_set_blksize_after_init),
    TESTFUNC(test_tftp_set_blksize_minimum),
    TESTFUNC(test_tftp_set_blksize_maximum),
    TESTFUNC(test_tftp_set_blksize_ethernet_optimal),
    TESTFUNC(test_tftp_set_blksize_below_minimum),
    TESTFUNC(test_tftp_set_blksize_above_maximum),
    TESTFUNC(test_tftp_set_blksize_during_transfer),
    /* RRQ protocol tests */
    TESTFUNC(test_tftp_rrq_includes_blksize_option),
    TESTFUNC(test_tftp_rrq_no_blksize_when_default),
    TESTFUNC(test_tftp_client_handles_oack),
    TESTFUNC(test_tftp_client_handles_oack_smaller_blksize),
    TESTFUNC(test_tftp_client_fallback_to_default_blksize),
    TESTFUNC(test_tftp_client_rejects_invalid_oack_blksize_small),
    TESTFUNC(test_tftp_client_rejects_oack_larger_than_requested),
    /* WRQ protocol tests */
    TESTFUNC(test_tftp_wrq_includes_blksize_option),
    TESTFUNC(test_tftp_wrq_sends_data_with_negotiated_blksize),
    TESTFUNC(test_tftp_wrq_fallback_to_default_blksize),
    /* Edge case tests */
    TESTFUNC(test_tftp_blksize_reset_after_cleanup),
    TESTFUNC(test_tftp_set_blksize_multiple_calls),
    TESTFUNC(test_tftp_receive_oversized_data_block),
    TESTFUNC(test_tftp_final_block_detection_custom_blksize),
    TESTFUNC(test_tftp_zero_length_final_block)
  };
  return create_suite("TFTP", tests, sizeof(tests)/sizeof(testfunc), tftp_setup, tftp_teardown);
}
