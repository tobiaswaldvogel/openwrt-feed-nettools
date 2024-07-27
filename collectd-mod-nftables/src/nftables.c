/**
 * collectd - src/nftables.c
 * Copyright (C) 2024 Tobias Waldvogel
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>

#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#define PLUGIN_NAME "nftables"

/* Max size of rule lookup query */
#define QUERY_SIZE \
  sizeof(struct nlmsghdr) + \
  sizeof(struct nfgenmsg) + \
  sizeof(struct nlattr) + NFT_TABLE_MAXNAMELEN + \
  sizeof(struct nlattr) + NFT_CHAIN_MAXNAMELEN + \
  sizeof(struct nlattr) + sizeof(uint64_t)

/*
 * Definitions for rule comments in userdata attributes
 * Borrowed from libfntnl 
 *
 * libnftnl itself is not used as it has too much overhead
 * for frequent polling
 */
#define NFTNL_UDATA_RULE_COMMENT 0
struct nftnl_udata {
  uint8_t         type;
  uint8_t         len;
  unsigned char   value[];
} __attribute__((__packed__));

static const char NAMED_COUNTERS_INSTANCE[] = "Named counters";

/*
 * (Module-)Global variables
 */
struct nlmsghdr *all_rules;           /* Query for all rules                */
struct nlmsghdr *all_named_counters;  /* Qeury for all named counters       */
struct mnl_socket *nl = NULL;         /* netlink socket                     */
uint32_t portid;                      /* portid for netlink connection      */

/*
 * Counter definition
 */
typedef struct {
  char            *name;            /* Counter name or rule comment         */
  uint32_t        name_len;         /* Name length for lookup via comment   */
  char            *chain;           /* Chain name in case of rule counter   */
  uint64_t        handle;           /* Rule handle                          */
  struct nlmsghdr *query;           /* Query for looking up rule by handle  */
  value_list_t    vl_packets;       /* Value list for dispatching packets   */
  value_list_t    vl_bytes;         /* Value list for dispatching bytes     */
  int             skip_dispatch;
} ctr_t;

/* Arrays for named counters and rule counters */
static ctr_t *ctrs_rule = NULL, *ctrs_named = NULL;
static int   ctrs_rule_len = 0,  ctrs_named_len = 0;
static int   ignore_selected = 0;   /* Include or exclude counters          */
static int   rule_dump = 1;         /* Request full dump for handle lookup  */

/*
 * Connect to netlink
 */
static int nftables_connect()
{
  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL) {
    ERROR("%s plugin: mnl_socket_open failed", PLUGIN_NAME);
    return -1;
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    ERROR("%s plugin: mnl_socket_bind failed", PLUGIN_NAME);
    mnl_socket_close(nl);
    nl = NULL;
    return -1;
  }

  portid = mnl_socket_get_portid(nl);
  return 0;
} /* nftables_connect */

/*
 * Send request to netlink and process data with callback function
 *
 * For multi message responses the callback should return MNL_CB_OK
 * to continue the processing all items. The last DONE control
 * message is processed internally and returns automaticlly MNL_CB_STOP
 *
 * For a single message the callback should return MNL_CB_STOP or MNL_CB_ERROR
 * Returning MNL_CB_OK would result in waiting forever in recvfrom 
 */
static int nftables_run_query(struct nlmsghdr *query, mnl_cb_t cb_data, void *ctx)
{
  int ret;
  char nlh_buf[MNL_SOCKET_BUFFER_SIZE];

  if (!nl)
    if (nftables_connect())
	  return -2;

  if (mnl_socket_sendto(nl, query, query->nlmsg_len) < 0) {
    ERROR("%s plugin: mnl_socket_send failed", PLUGIN_NAME);
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

/*
 * Set type instance from prefix and name
 */
static void nftables_set_type_instance(value_list_t *vl,
                                       const char *prefix, const char *name)
{
  if (prefix)
    ssnprintf(vl->type_instance, sizeof(vl->type_instance),
              "%s %s", prefix, name);
  else
    sstrncpy(vl->type_instance, name, sizeof(vl->type_instance));
}

/*
 * Add named or rule counter config
 * The value list is already created inside the counter structure
 * to avoid copying the plugin and data type strings with every read.
 */
static int nftables_config_counter(oconfig_item_t *ci, const char *instance)
{
  ctr_t           **ctrs_list, *new_list, *ctr;
  int             *ctrs_list_len;
  value_list_t    *vl;
  const char      *name, *chain, *display;
  int             idx;

  for (idx = 0; idx < ci->values_num; idx++)
    if (ci->values[idx].type != OCONFIG_TYPE_STRING) {
      ERROR("%s plugin: Only string arguments are allowed for option `%s'.",
            PLUGIN_NAME, ci->key);
      return -1;
    }

  if (strcasecmp("Counter", ci->key) == 0) {
    if (ci->values_num < 2) {
      ERROR("%s plugin: The `%s' option requires at least two string argument.",
            PLUGIN_NAME, ci->key);
      return -1;
    }

    ctrs_list     = &ctrs_named;
    ctrs_list_len = &ctrs_named_len;
    idx = 0;
    name  = ci->values[idx++].value.string;
    chain = 0;

  } else if (strcasecmp("Rule", ci->key) == 0) {
    if (ci->values_num < 1) {
      ERROR("%s plugin: The `%s' option requires at least one string argument.",
            PLUGIN_NAME, ci->key);
      return -1;
    }

    ctrs_list     = &ctrs_rule;
    ctrs_list_len = &ctrs_rule_len;
    idx = 0;
    chain = ci->values[idx++].value.string;
    name  = ci->values[idx++].value.string;

  } else {
    ERROR("%s plugin: Unknown config option: %s", PLUGIN_NAME, ci->key);
    return -1;
  }

  display = idx < ci->values_num ? ci->values[idx].value.string : 0;

  new_list = realloc(*ctrs_list, (*ctrs_list_len + 1) * sizeof(*new_list));
  if (new_list == NULL) {
    ERROR("%s plugin: realloc failed: %s", PLUGIN_NAME, STRERRNO);
    return -1;
  }

  *ctrs_list = new_list;
  ctr = new_list + *ctrs_list_len;
  memset(ctr, 0, sizeof(*ctr));

  ctr->name = strdup(name);
  ctr->name_len = strlen(ctr->name) + 1; /* including \0 */
  ctr->chain = chain ? strdup(chain) : NULL;

  vl = &(ctr->vl_packets);
  sstrncpy(vl->plugin, PLUGIN_NAME, sizeof(vl->plugin));
  sstrncpy(vl->plugin_instance, instance, sizeof(vl->plugin_instance));
  if (display)
    nftables_set_type_instance(vl, 0, display);
  else
    nftables_set_type_instance(vl, chain, name);
  
  sstrncpy(vl->type, "packets", sizeof(vl->type));
  vl->values_len = 1;

  memcpy(&(ctr->vl_bytes), vl, sizeof(*vl));
  vl = &(ctr->vl_bytes);
  sstrncpy(vl->type, "total_bytes", sizeof(vl->type));

  (*ctrs_list_len)++;
  return 0;
}

static int nftables_config(oconfig_item_t *ci)
{
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (!child->children_num) {
      if (strcasecmp("IgnoreSelected", child->key) == 0)
        ignore_selected = 1;

      else if (nftables_config_counter(child, ""))
        return 1;

      continue;
    }

    if (strcasecmp("Instance", child->key) != 0) {
      ERROR("%s plugin: Unknown config option: %s", PLUGIN_NAME, child->key);
      return 1;
    }

    /* Instance definition */
    if ((child->values_num == 0) || (child->values[0].type != OCONFIG_TYPE_STRING)) {
      ERROR("%s plugin: Section '%s' cannot be anonymous.", PLUGIN_NAME, child->key);
      return -1;
    }

    const char *instance = child->values[0].value.string;

    for (int c = 0; c < child->children_num; c++)
      if (nftables_config_counter(child->children + c, instance))
        return -1;
  }

  return 0;
}

/*
 * Dispatch counter, without prepared pre-build value list
 */
static void nftables_dispatch_counter(const char *plugin_instance,
                                      const char *chain,
                                      const char *name,
									                    int have_bytes, int have_packets,
                                      uint64_t bytes, uint64_t packets)
{
  value_list_t vl = VALUE_LIST_INIT;
  vl.values_len = 1;

  sstrncpy(vl.plugin, PLUGIN_NAME, sizeof(vl.plugin));
  if (plugin_instance)
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  else
    vl.plugin_instance[0] = 0;
  nftables_set_type_instance(&vl, chain, name);

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
} /* nftables_dispatch_counter */

/*
 * Parse nested counter attributes and dispatch values
 */
static void nftables_parse_counter(struct nlattr *ctr_data, ctr_t *ctr,
                                   const char *plugin_instance,
                                   const char *prefix, const char *name)
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
	  nftables_dispatch_counter(plugin_instance, prefix, name,
                              have_bytes, have_packets,
	                            bytes, packets);
} /* nftables_parse_counter */

/*
 * Receives named counters and filters them according to config
 * This callback is always used with NLM_F_DUMP => return MNL_CB_OK
 */
static int nftables_read_named_counter_cb(const struct nlmsghdr *nlh, void *unused)
{
  int               type;
  struct nfgenmsg   *nfg = mnl_nlmsg_get_payload(nlh);
  struct nlattr     *attr, *ctr_attr = NULL;
  const char        *name = NULL;

  /* Get name and counter object */
  mnl_attr_for_each(attr, nlh, sizeof(*nfg)) {
    type = mnl_attr_get_type(attr);
    if (type == NFTA_OBJ_TYPE) { /* sanity check */
      if (htobe32(mnl_attr_get_u32(attr)) != NFT_OBJECT_COUNTER)
        return MNL_CB_OK;

	  } else if (type == NFTA_OBJ_NAME) {
	    name = mnl_attr_get_str(attr);
	  } else if (type == NFTA_OBJ_DATA) {
  	  ctr_attr = attr;
  	}
  }

  if (!ctrs_named_len) { /* Unfiltered, all name counters */
    nftables_parse_counter(ctr_attr, NULL, NAMED_COUNTERS_INSTANCE, NULL, name); 
    return MNL_CB_OK;
  }

  ctr_t *ctr;

  if (ignore_selected) {  /* Ignore selected anmed counters */
    for (ctr = ctrs_named; ctr < ctrs_named + ctrs_named_len; ctr++)
      if (0 == strcmp(name, ctr->name))
        return MNL_CB_OK;

    nftables_parse_counter(ctr_attr, NULL, NAMED_COUNTERS_INSTANCE, NULL, name);
    return MNL_CB_OK;
  }

  /* Include selected counters only */
  for (ctr = ctrs_named; ctr < ctrs_named + ctrs_named_len; ctr++)
    if (0 == strcmp(name, ctr->name))
      nftables_parse_counter(ctr_attr, ctr, NULL, NULL, NULL);
      /* Continue as there might be several instances */

  return MNL_CB_OK;
}

/*
 * Process get rule messages
 * It might be called from a single request for lookup by handle with ctx set
 * or from a NLM_F_DUMP request without ctx
 * Counters are stored in expression attributes and only the first counter
 * is taken into account. The comment is placed in the userdata attribute
 */
static int nftables_read_rule_counter_cb(const struct nlmsghdr *nlh, void *ctx)
{
  uint16_t			      flags = nlh->nlmsg_flags;
  int                 type;
  uint64_t            handle = 0;
  struct nfgenmsg     *nfg = mnl_nlmsg_get_payload(nlh);
  struct nlattr       *attr, *nested_attr, *expr, *ctr_attr;
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

  if (!exprs) /* Rule without any expressions*/
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;

  if (ctx) {
	  ctr_t *ctr = ctx;

	  if (handle != ctr->handle) {
      /* Sanity, check but should never happen */
		  ERROR("Rule has wrong handle. Expected %" PRIu64 ", "
                   "received %" PRIu64 " !\n", ctr->handle, handle);
		  return MNL_CB_ERROR;
	  }

  } else if (!table || !chain || !comment
             || comment->type != NFTNL_UDATA_RULE_COMMENT)
      return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;
    
  /* Find first counter */
  mnl_attr_for_each_nested(expr, exprs) {
    ctr_attr = 0;

    mnl_attr_for_each_nested(nested_attr, expr) {
      type = mnl_attr_get_type(nested_attr);
      if (type == NFTA_EXPR_NAME) {
        if (strcmp("counter", mnl_attr_get_str(nested_attr))) {
          /* Not a counter */
          ctr_attr = 0;
          break;
        }

	    } else if (type == NFTA_EXPR_DATA)
          ctr_attr = nested_attr;
  	}

    if (ctr_attr)
	    break;
  }

  if (!ctr_attr) /* No counters in this rule */
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_ERROR;

  if (ctx) {
    /* Individual rule */
    nftables_parse_counter(ctr_attr, ctx, NULL, NULL, NULL);
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_STOP;
  }

  /* In case of all or ignore selected use chain as plugin instance */
  if (!ctrs_rule_len) { /* Unfiltered */
    nftables_parse_counter(ctr_attr, 0, mnl_attr_get_str(chain),
                           NULL,
                           (const char*)comment->value);
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_STOP;
  }

  if (ignore_selected) {  /* Ignore selected rule counters */
    for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++)
      if (comment->len == ctr->name_len &&
          0 == strcmp((const char*)comment->value, ctr->name) &&
          0 == strcmp(mnl_attr_get_str(chain), ctr->chain))
        return MNL_CB_OK;

    nftables_parse_counter(ctr_attr, 0, mnl_attr_get_str(chain),
                           NULL,
                           (const char*)comment->value);
    return (flags & NLM_F_MULTI) ? MNL_CB_OK : MNL_CB_STOP;
  }

  /* Update rule query */
  for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++) {
	  if (comment->len != ctr->name_len ||
        strcmp((const char*)comment->value, ctr->name) ||
        strcmp(mnl_attr_get_str(chain), ctr->chain))
      continue;

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
    DEBUG("%s plugin: %s %s resolved to handle %ld",
          PLUGIN_NAME, ctr->chain, ctr->name, ctr->handle);
    
    if (!ctr->skip_dispatch)
      nftables_parse_counter(ctr_attr, ctr, NULL, NULL, NULL);
    
    break;
  }
  return MNL_CB_OK;
}

static int nftables_resolve_rule_counters(void)
{
  ctr_t *ctr;

  for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++)
    if (ctr->query)
      ctr->query->nlmsg_len = 0;

  return nftables_run_query(all_rules, nftables_read_rule_counter_cb, 0);
}

/*
 * Read strategy for named counters:
 *   Named counters are matched against the name attribute
 *   All named counters are read with a single request for all counter objects
 *   and then filtered
 * 
 * Read strategy for rule counters:
 *   Rule counters are matched against the comment in the userdata.
 *   Reading all rules fetches also rules with no counter expressions or 
 *   comments and usually only a few are selected
 *   To improve performance and reduce the overhead with individually selected
 *   rules, first all rules are read and then the handle is saved. In the
 *   subsequent reads they can be accessed directly with the handle.
 *   If a lookup by handle fails then another full dump is triggered as the
 *   handle might have changed. (e.g. firewall reload)
 */
static int nftables_read(void) {
  ctr_t *ctr;
  int   ret;

  if (ignore_selected || (!ctrs_named_len && !ctrs_rule_len)) {
    /* All counters are selected or only a few exlcuded
       => Best stragey is reading all counters */
    nftables_run_query(all_named_counters, nftables_read_named_counter_cb, 0);
    nftables_run_query(all_rules, nftables_read_rule_counter_cb, 0);
    return 0;
  }

  /* Only individual counters are select */
  if (ctrs_named_len) /* Collect named counters */
    nftables_run_query(all_named_counters, nftables_read_named_counter_cb, 0);

  if (!ctrs_rule_len)
    return 0;

  /* Collect rule counters */
  if (rule_dump) {
    rule_dump = 0;
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

      /* Avoid dispatching processed counters again */
      for (ctr_skip = ctrs_rule; ctr_skip < ctr; ctr_skip++)
        ctr_skip->skip_dispatch = 1;

      nftables_resolve_rule_counters();

      for (ctr_skip = ctrs_rule; ctr_skip < ctr; ctr_skip++)
        ctr_skip->skip_dispatch = 0;

      /* Force reading all rules again one more time as the update
        * modification might still not be complete */
      rule_dump = 1; 
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

  /* Query for all rules */
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

  /* Query for all objects filtered by counters */
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
} /* void nftables_build_queries */

static int nftables_shutdown(void) {
  ctr_t *ctr;

  if (all_rules)
    free(all_rules);

  if (ctrs_rule) {
    for (ctr = ctrs_rule; ctr < ctrs_rule + ctrs_rule_len; ctr++) {
      if (ctr->name)
        free(ctr->name);

      if (ctr->query)
        free(ctr->query);
    }
    free(ctrs_rule);
  }

  if (all_named_counters)
    free(all_named_counters);

  if (ctrs_named) {
    for (ctr = ctrs_named; ctr < ctrs_named + ctrs_named_len; ctr++) {
      if (ctr->name)
        free(ctr->name);
    }
    free(ctrs_named);
  }

  if (nl)
    mnl_socket_close(nl);

  return 0;
} /* int nftables_shutdown */

static int nftables_init(void) {
#if defined(HAVE_SYS_CAPABILITY_H) && defined(CAP_NET_ADMIN)
  if (check_capability(CAP_NET_ADMIN) != 0) {
    if (getuid() == 0)
      WARNING("%s plugin: Running collectd as root, but the "
              "CAP_NET_ADMIN capability is missing. The plugin's read "
              "function will probably fail. Is your init system dropping "
              "capabilities?",
              PLUGIN_NAME);
    else
      WARNING("%s plugin: collectd doesn't have the CAP_NET_ADMIN "
              "capability. If you don't want to run collectd as root, try "
              "running \"setcap cap_net_admin=ep\" on the collectd binary.",
              PLUGIN_NAME);
  }
#endif

  nftables_build_queries();
  return 0;
} /* int nftables_init */

void module_register(void) {
  plugin_register_complex_config(PLUGIN_NAME, nftables_config);
  plugin_register_init(PLUGIN_NAME, nftables_init);
  plugin_register_read(PLUGIN_NAME, nftables_read);
  plugin_register_shutdown(PLUGIN_NAME, nftables_shutdown);
}
