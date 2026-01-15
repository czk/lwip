/**
 * @file
 * HTTPD SSI handler for configuration display
 *
 * This module provides SSI handlers to display lwIP configuration
 * values on web pages, including TFTP blksize and other settings.
 * Also provides CGI handlers for modifying configuration values.
 */

#include "lwip/opt.h"
#include "config_ssi.h"

#include "lwip/apps/httpd.h"
#include "lwip/def.h"
#include "lwip/netif.h"
#include "lwip/init.h"
#include "lwip/apps/tftp_opts.h"
#include "lwip/apps/tftp_client.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if LWIP_HTTPD_SSI

/* TFTP block size - default value */
#ifndef TFTP_MAX_PAYLOAD_SIZE
#define TFTP_MAX_PAYLOAD_SIZE 512
#endif

/**
 * SSI handler callback for configuration tags
 */
static u16_t
config_ssi_handler(const char *ssi_tag_name, char *pcInsert, int iInsertLen)
{
  size_t printed = 0;

  /* TFTP Configuration */
  if (!strcmp(ssi_tag_name, "tftp_blk")) {
    printed = snprintf(pcInsert, iInsertLen, "%d", tftp_client_get_blksize());
  }
  else if (!strcmp(ssi_tag_name, "tftp_port")) {
    printed = snprintf(pcInsert, iInsertLen, "%d", TFTP_PORT);
  }
  else if (!strcmp(ssi_tag_name, "tftp_timo")) {
    printed = snprintf(pcInsert, iInsertLen, "%d", TFTP_TIMEOUT_MSECS);
  }
  else if (!strcmp(ssi_tag_name, "tftp_rtry")) {
    printed = snprintf(pcInsert, iInsertLen, "%d", TFTP_MAX_RETRIES);
  }
  /* Network Configuration */
  else if (!strcmp(ssi_tag_name, "net_ip")) {
    if (netif_default != NULL) {
      printed = snprintf(pcInsert, iInsertLen, "%s",
                         ip4addr_ntoa(netif_ip4_addr(netif_default)));
    } else {
      printed = snprintf(pcInsert, iInsertLen, "N/A");
    }
  }
  else if (!strcmp(ssi_tag_name, "net_mask")) {
    if (netif_default != NULL) {
      printed = snprintf(pcInsert, iInsertLen, "%s",
                         ip4addr_ntoa(netif_ip4_netmask(netif_default)));
    } else {
      printed = snprintf(pcInsert, iInsertLen, "N/A");
    }
  }
  else if (!strcmp(ssi_tag_name, "net_gw")) {
    if (netif_default != NULL) {
      printed = snprintf(pcInsert, iInsertLen, "%s",
                         ip4addr_ntoa(netif_ip4_gw(netif_default)));
    } else {
      printed = snprintf(pcInsert, iInsertLen, "N/A");
    }
  }
  else if (!strcmp(ssi_tag_name, "net_mac")) {
    if (netif_default != NULL) {
      printed = snprintf(pcInsert, iInsertLen,
                         "%02X:%02X:%02X:%02X:%02X:%02X",
                         netif_default->hwaddr[0], netif_default->hwaddr[1],
                         netif_default->hwaddr[2], netif_default->hwaddr[3],
                         netif_default->hwaddr[4], netif_default->hwaddr[5]);
    } else {
      printed = snprintf(pcInsert, iInsertLen, "N/A");
    }
  }
  /* TCP Configuration */
  else if (!strcmp(ssi_tag_name, "tcp_mss")) {
    printed = snprintf(pcInsert, iInsertLen, "%d bytes", TCP_MSS);
  }
  else if (!strcmp(ssi_tag_name, "tcp_wnd")) {
    printed = snprintf(pcInsert, iInsertLen, "%d bytes", TCP_WND);
  }
  else if (!strcmp(ssi_tag_name, "tcp_sndbuf")) {
    printed = snprintf(pcInsert, iInsertLen, "%d bytes", TCP_SND_BUF);
  }
  /* Memory Configuration */
  else if (!strcmp(ssi_tag_name, "mem_size")) {
    printed = snprintf(pcInsert, iInsertLen, "%d bytes", MEM_SIZE);
  }
  else if (!strcmp(ssi_tag_name, "pbuf_pool")) {
    printed = snprintf(pcInsert, iInsertLen, "%d", PBUF_POOL_SIZE);
  }
  else if (!strcmp(ssi_tag_name, "pbuf_bufsz")) {
    printed = snprintf(pcInsert, iInsertLen, "%d bytes", PBUF_POOL_BUFSIZE);
  }
  /* lwIP Version */
  else if (!strcmp(ssi_tag_name, "lwip_ver")) {
    printed = snprintf(pcInsert, iInsertLen, "%s", LWIP_VERSION_STRING);
  }
  /* Unknown tag */
  else {
    printed = snprintf(pcInsert, iInsertLen, "???");
  }

  return (u16_t)printed;
}

#if LWIP_HTTPD_CGI

/**
 * CGI handler for setting TFTP block size
 * URL: /set_blksize?blksize=<value>
 */
static const char *
cgi_set_blksize(int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
{
  int i;

  LWIP_UNUSED_ARG(iIndex);

  for (i = 0; i < iNumParams; i++) {
    if (!strcmp(pcParam[i], "blksize")) {
      int blksize = atoi(pcValue[i]);
      if (blksize >= 8 && blksize <= 65464) {
        tftp_client_set_blksize((u16_t)blksize);
      }
      break;
    }
  }

  /* Return to configuration page */
  return "/config.shtml";
}

static const tCGI config_cgi_handlers[] = {
  { "/set_blksize", cgi_set_blksize }
};

#endif /* LWIP_HTTPD_CGI */

void
config_ssi_init(void)
{
  http_set_ssi_handler(config_ssi_handler, NULL, 0);
#if LWIP_HTTPD_CGI
  http_set_cgi_handlers(config_cgi_handlers, LWIP_ARRAYSIZE(config_cgi_handlers));
#endif
}

#endif /* LWIP_HTTPD_SSI */
