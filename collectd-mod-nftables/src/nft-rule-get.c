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
#include <string.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#define PLUGIN_NAME "nftables"

#define sstrncpy strncpy
#undef ERROR
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
  value_list_t    vl_packets;
  value_list_t    vl_bytes;
  int             skip_dispatch;
} ctr_t;

static ctr_t *ctrs_rule = NULL, *ctrs_named = NULL;
static int   ctrs_rule_len = 0,  ctrs_named_len = 0;

struct nlmsghdr *all_rules;
struct nlmsghdr *all_named_counters;
struct mnl_socket *nl = NULL;
uint32_t portid;

int plugin_dispatch_values(value_list_t const *vl) {
  printf("Dispatch %s%s%s %s-%s, %ld\n",
    vl->plugin, vl->plugin_instance[0] ? "-" : "", vl->plugin_instance,
    vl->type, vl->type_instance,
	vl->values->derive);
  return 0;
}

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

static void add_counter(ctr_t **ctrs_list, int *ctrs_list_len,
	                    const char *name, const char *display, const char *instance) {
  ctr_t         *list, *ctr;
  value_list_t  *vl;
  
  list = realloc(*ctrs_list, (*ctrs_list_len + 1) * sizeof(*list));
  *ctrs_list = list;
  ctr = list + *ctrs_list_len;
  memset(ctr, 0, sizeof(*ctr));

  ctr->name = strdup(name);
  ctr->name_len = strlen(ctr->name) + 1; /* including \0 */

  vl = &(ctr->vl_packets);
  sstrncpy(vl->plugin, PLUGIN_NAME, sizeof(vl->plugin));
  sstrncpy(vl->plugin_instance, instance, sizeof(vl->plugin_instance));
  sstrncpy(vl->type_instance, display ? display : name, sizeof(vl->type_instance));
  sstrncpy(vl->type, "packets", sizeof(vl->type));
  vl->values_len = 1;

  memcpy(&(ctr->vl_bytes), vl, sizeof(*vl));
  vl = &(ctr->vl_bytes);
  sstrncpy(vl->type, "total_bytes", sizeof(vl->type));

  (*ctrs_list_len)++;
}





static void nftables_dispatch_counter(const char *plugin_instance,
                                      const char *type_instance,
									  int have_bytes, int have_packets,
                                      uint64_t bytes, uint64_t packets)
{
  value_list_t vl = VALUE_LIST_INIT;
  vl.values_len = 1;

  sstrncpy(vl.plugin, PLUGIN_NAME, sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  if (have_packets) {
    sstrncpy(vl.type, "packets", sizeof(vl.type));
    vl.values = &(value_t){.derive = (derive_t)packets};
    plugin_dispatch_values(&vl);
  }
  
  if (have_bytes) {
    sstrncpy(vl.type, "total_bytes", sizeof(vl.type));
    vl.values = &(value_t){.derive = (derive_t)bytes};
    plugin_dispatch_values(&vl);
  }
}

static void nftables_parse_counter(struct nlattr *ctr_data, const char *name, ctr_t *ctr)
{
  uint64_t          packets, bytes;
  int				        have_packets, have_bytes;
  struct nlattr     *ctr_attr;
  int               type;

  if (!ctr_data)
    return;

  have_packets = have_bytes = packets = bytes = 0;
  mnl_attr_for_each_nested(ctr_attr, ctr_data) {
    type = mnl_attr_get_type(ctr_attr);
    if (type == NFTA_COUNTER_BYTES) {
      bytes = be64toh(mnl_attr_get_u64(ctr_attr));
  	  have_bytes = 1;
    } else if (type == NFTA_COUNTER_PACKETS) {
      packets = be64toh(mnl_attr_get_u64(ctr_attr));
	    have_packets = 1;
	  }
  }

  if (ctr) {
    if (have_packets) {
      ctr->vl_packets.values = &(value_t){.derive = (derive_t)packets};
      plugin_dispatch_values(&(ctr->vl_packets));
	  }

    if (have_bytes) {
      ctr->vl_bytes.values = &(value_t){.derive = (derive_t)bytes};
      plugin_dispatch_values(&(ctr->vl_bytes));
	  }

  } else if (name)
	  nftables_dispatch_counter("", name, have_bytes, have_packets,
	                                      bytes, packets);
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

static int nftables_read_rule_counter_cb(const struct nlmsghdr *nlh, void *ctx)
{
  uint16_t			      flags = nlh->nlmsg_flags;
  int                 type;
  uint64_t            handle = 0;
  struct nfgenmsg     *nfg = mnl_nlmsg_get_payload(nlh);
  struct nlattr       *attr, *nested_attr, *expr, *ctr_data;
  struct nlattr       *table, *chain, *exprs;
  struct nftnl_udata  *comment;
  ctr_t               *ctr;

  table = chain = exprs = NULL;
  comment = NULL;
  mnl_attr_for_each(attr, nlh, sizeof(*nfg)) {
    type = mnl_attr_get_type(attr);
    if (type == NFTA_RULE_TABLE)
      table = attr;

    else if (type == NFTA_RULE_CHAIN)
      chain = attr;

    else if (type == NFTA_RULE_HANDLE)
      handle = be64toh(mnl_attr_get_u64(attr));

    else if (type == NFTA_RULE_USERDATA)
      comment = mnl_attr_get_payload(attr);

    else if (type == NFTA_RULE_EXPRESSIONS)
      exprs = attr;
  }

  if (!exprs)
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;

  if (ctx) {
	  ctr_t *ctr = ctx;

	  if (handle != ctr->handle) {
      /* Sanity check but should never happen */
		  ERROR("Rule has wrong handle. Expected %" PRIu64 ", "
                   "received %" PRIu64 " !\n", ctr->handle, handle);
		  return MNL_CB_ERROR;
	  }

  } else if (!table || !chain || !comment
             || comment->type != NFTNL_UDATA_RULE_COMMENT)
      return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;
    
  /* Find first counter */
  mnl_attr_for_each_nested(expr, exprs) {
    ctr_data = 0;

    mnl_attr_for_each_nested(nested_attr, expr) {
      type = mnl_attr_get_type(nested_attr);
      if (type == NFTA_EXPR_NAME) {
        if (strcmp("counter", mnl_attr_get_str(nested_attr))) {
          /* Not a counter */
          ctr_data = 0;
          break;
        }

	    } else if (type == NFTA_EXPR_DATA)
          ctr_data = nested_attr;
  	}

    if (ctr_data)
	    break;
  }

  if (!ctr_data)
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;

  if (ctx) {
    /* Individual rule */
    ctr = ctx;

    nftables_parse_counter(ctr_data, ctr->name, ctr);
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_STOP;
  }

  if (!ctrs_rule_len) { /* Unfiltered */
    nftables_parse_counter(ctr_data, (const char*)comment->value, 0);
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_STOP;
  }

  /* Update rule query */
  for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++) {
	  if (comment->len == ctr->name_len &&
        0 == strcmp((const char*)comment->value, ctr->name)) {
      if (!ctr->query)
        ctr->query = malloc(QUERY_SIZE);

      struct nlmsghdr *query;
      struct nfgenmsg *query_header;
      uint32_t family = nfg->nfgen_family;

      query = mnl_nlmsg_put_header(ctr->query);
      query->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE;
      query->nlmsg_flags = NLM_F_REQUEST;
      query->nlmsg_seq = 0;
      query_header = mnl_nlmsg_put_extra_header(query, sizeof(*query_header));
      query_header->nfgen_family = family;
      query_header->version = NFNETLINK_V0;
      query_header->res_id = 0;
      mnl_attr_put_strz(query, NFTA_RULE_TABLE, mnl_attr_get_str(table));
      mnl_attr_put_strz(query, NFTA_RULE_CHAIN, mnl_attr_get_str(chain));
      mnl_attr_put_u64(query, NFTA_RULE_HANDLE, htobe64(handle));

      ctr->handle = handle;
  printf("%s resolved to handle %ld\n", ctr->name, ctr->handle);
      
      if (!ctr->skip_dispatch)
        nftables_parse_counter(ctr_data, (const char*)comment, ctr);
      
      break;
    }
  }
  return MNL_CB_OK;
}

int resolve = 1;

static int nftables_resolve_rule_counters(void)
{
  ctr_t *ctr;

  for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++)
    if (ctr->query)
      ctr->query->nlmsg_len = 0;

  return nftables_run_query(all_rules, nftables_read_rule_counter_cb, 0);
}

static int nftables_read(void) {
  ctr_t *ctr;
  int   ret;

  if (!ctrs_named_len && !ctrs_rule_len) {
    nftables_run_query(all_named_counters, nftables_read_named_counter_cb, 0);
    nftables_run_query(all_rules, nftables_read_rule_counter_cb, 0);
    return 0;
  }

  if (ctrs_named_len)
    nftables_run_query(all_named_counters, nftables_read_named_counter_cb, 0);

  if (resolve) {
    resolve = 0;
    nftables_resolve_rule_counters();
    return 0;
  }

  /* Try to read the rules directly by handle for better performance
   * If that fails the rule handle might have changed and all rules
   * are read again for lookup via comment */
  for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++) {
    if (!ctr->query || !ctr->query->nlmsg_len)
      continue;

    ret = nftables_run_query(ctr->query, nftables_read_rule_counter_cb, ctr);
    if (ret == MNL_CB_ERROR) {
      ctr_t *ctr_skip;

      /* Avoid dispatching again */
      for (ctr_skip = ctrs_rule; ctr_skip < ctr; ctr_skip++)
        ctr_skip->skip_dispatch = 1;

      nftables_resolve_rule_counters();

      for (ctr_skip = ctrs_rule; ctr_skip < ctr; ctr_skip++)
        ctr_skip->skip_dispatch = 0;

      /* Force reading all rules again one more time as the update
        * modification might still not be complete */
      resolve = 1; 
      break;
    }
  }

  return 0;
} /* int nftables_read */

static void nftables_build_queries()
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;
  struct nfgenmsg *nfh;

  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nlh->nlmsg_seq = 0;
  nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfh));
  nfh->nfgen_family = NFPROTO_UNSPEC;
  nfh->version = NFNETLINK_V0;
  nfh->res_id = 0;


  all_rules = malloc(nlh->nlmsg_len);
  memcpy(all_rules, nlh, nlh->nlmsg_len);

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
  if (1) {
    add_counter(&ctrs_rule, &ctrs_rule_len, "!fw4: Allow-Ping", "block_rm2", "Block");
	add_counter(&ctrs_rule, &ctrs_rule_len, "does not exist", "doesnot_rm2", "Block");
	add_counter(&ctrs_rule, &ctrs_rule_len, "!fw4: SMTP", "doesnot_rm2", "Block");
  }

  if (1) {
	add_counter(&ctrs_named, &ctrs_named_len, "cnt_reject_from_wan_ssh", "ssh", "Block");
  }

    nftables_build_queries();

    while (1) {
      nftables_read();
	  printf("Sleep\n\n\n");
	  sleep(5);
	}

    if (nl)
	  mnl_socket_close(nl);

	return EXIT_SUCCESS;
}
