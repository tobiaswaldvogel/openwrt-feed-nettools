/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>

#include <endian.h>

#define sstrncpy strncpy
#define ERROR printf

#define QUERY_SIZE \
  sizeof(struct nlmsghdr) + \
  sizeof(struct nfgenmsg) + \
  sizeof(struct nlattr) + NFT_TABLE_MAXNAMELEN + \
  sizeof(struct nlattr) + NFT_CHAIN_MAXNAMELEN + \
  sizeof(struct nlattr) + sizeof(uint64_t)

#define NFTNL_UDATA_RULE_COMMENT 0
struct nftnl_udata {
        uint8_t         type;
        uint8_t         len;
        unsigned char   value[];
} __attribute__((__packed__));

typedef struct {
  char            *name;
  uint32_t        name_len;
  uint64_t        handle;
  struct nlmsghdr *query;
} ctr_t;

static ctr_t *ctrs_named = NULL;
static int   ctrs_named_len = 0;

struct nlmsghdr *all_named_counters;
struct mnl_socket *nl = NULL;
uint32_t portid;

static int nftables_connect()
{
  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL) {
    ERROR("nftables plugin: mnl_socket_open failed");
    return -1;
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    ERROR("nftables plugin: mnl_socket_bind failed");
    mnl_socket_close(nl);
    nl = NULL;
    return -1;
  }

  portid = mnl_socket_get_portid(nl);
  return 0;
}

static int nftables_run_query(struct nlmsghdr *query, mnl_cb_t cb_data, void *ctx)
{
  int ret;
  char nlh_buf[MNL_SOCKET_BUFFER_SIZE];

  if (!nl)
    if (nftables_connect())
	  return -2;

  if (mnl_socket_sendto(nl, query, query->nlmsg_len) < 0) {
    ERROR("nftables plugin: mnl_socket_send failed");
    mnl_socket_close(nl);
    nl = NULL;
    return -2;
  }

  ret = mnl_socket_recvfrom(nl, nlh_buf, sizeof(nlh_buf));
  while (ret > 0) {
    ret = mnl_cb_run(nlh_buf, ret, 0, portid, cb_data, ctx);
    if (ret <= 0)
      break;
    ret = mnl_socket_recvfrom(nl, nlh_buf, sizeof(nlh_buf));
  }

  return ret;
}

static void add_counter(ctr_t **ctrs_list, int *ctrs_list_len, const char *name) {
  ctr_t         *list, *ctr;
  
  list = realloc(*ctrs_list, (*ctrs_list_len + 1) * sizeof(*list));
  *ctrs_list = list;
  ctr = list + *ctrs_list_len;
  memset(ctr, 0, sizeof(*ctr));

  ctr->name = strdup(name);
  ctr->name_len = strlen(ctr->name) + 1; /* including \0 */
  (*ctrs_list_len)++;
}

static void nftables_parse_counter(struct nlattr *ctr_data, const char *name, ctr_t *ctr)
{
  uint64_t          packets;
  int               have_packets;
  struct nlattr     *ctr_attr;
  int               type;

  if (!ctr_data)
    return;

  have_packets = packets = 0;
  mnl_attr_for_each_nested(ctr_attr, ctr_data) {
    type = mnl_attr_get_type(ctr_attr);
    if (type == NFTA_COUNTER_PACKETS) {
      packets = be64toh(mnl_attr_get_u64(ctr_attr));
	    have_packets = 1;
	  }
  }

  if (have_packets) {
    printf("%" PRIu64 " ", packets);
  }
}

static int nftables_read_named_counter_cb(const struct nlmsghdr *nlh, void *unused)
{
  int               type;
  uint16_t			flags = nlh->nlmsg_flags;
  struct nfgenmsg   *nfg = mnl_nlmsg_get_payload(nlh);
  struct nlattr     *attr, *data = NULL;
  const char        *name = NULL;

  mnl_attr_for_each(attr, nlh, sizeof(*nfg)) {
    type = mnl_attr_get_type(attr);
    if (type == NFTA_OBJ_TYPE) { /* sanity check */
      if (htobe32(mnl_attr_get_u32(attr)) != NFT_OBJECT_COUNTER)
        return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;

	  } else if (type == NFTA_OBJ_NAME) {
	    name = mnl_attr_get_str(attr);
	  } else if (type == NFTA_OBJ_DATA) {
  	  data = attr;
  	}
  }

  if (!ctrs_named_len)
    nftables_parse_counter(data, name, 0); /* Unfiltered */
  else {
	  ctr_t *ctr;

	  for (ctr = ctrs_named; ctr < ctrs_named + ctrs_named_len; ctr++)
	    if (0 == strcmp(name, ctr->name)) {
	      nftables_parse_counter(data, name, ctr);
		    break;
	    }
  } 

  return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_STOP;
}

static int nftables_read(void) {
  nftables_run_query(all_named_counters, nftables_read_named_counter_cb, 0);
  printf("\n");
  fflush(stdout);
  return 0;
} /* int nftables_read */

static void nftables_build_queries()
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;
  struct nfgenmsg *nfh;

  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETOBJ;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nlh->nlmsg_seq = 0;
  nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfh));
  nfh->nfgen_family = NFPROTO_UNSPEC;
  nfh->version = NFNETLINK_V0;
  nfh->res_id = 0;
  mnl_attr_put_u32(nlh, NFTA_OBJ_TYPE, htobe32(NFT_OBJECT_COUNTER));
  all_named_counters = malloc(nlh->nlmsg_len);
  memcpy(all_named_counters, nlh, nlh->nlmsg_len);
}

int main(int argc, char *argv[])
{
    int interval = 0;

    if (argc < 2) {
      printf("Usage: %s [-i <interval>] <counter-name>...\n", argv[0]);
      return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (strcmp(arg, "-i") == 0) {
            if (++i >= argc) {
                printf("Missing interval after -i\n");
                return EXIT_FAILURE;
            }
            interval = atoi(argv[i]);
            continue;
        }

        add_counter(&ctrs_named, &ctrs_named_len, arg);
    }

    nftables_build_queries();

    while (1) {
        nftables_read();
        if (!interval)
            break;
        sleep(interval);
    }

    if (nl)
	  mnl_socket_close(nl);

	return 0;
}
