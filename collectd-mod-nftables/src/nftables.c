/**
 * collectd - src/nftables.c
 * Copyright (C) 2023       Tobias Waldvogel
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
 *
 * Authors:
 *  Sjoerd van der Berg <harekiet at users.sourceforge.net>
 *  Florian Forster <octo at collectd.org>
 *  Marco Chiappero <marco at absence.it>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/object.h>

#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#define PLUGIN_NAME "nftables"

/*
 * (Module-)Global variables
 */
uint32_t seq;
uint32_t portid;

/*
 * Socket for communication with mnl
 */
struct mnl_socket *nl = NULL;
struct nlmsghdr *nlh = NULL;
char *nlh_buf = NULL;

#ifndef MAXNAMELEN
#define MAXNAMELEN 32
#endif
typedef struct {
  char counter[MAXNAMELEN];
  char display[MAXNAMELEN];
  char instance[MAXNAMELEN];
} ctr_t;

static ctr_t *ctr_list = NULL;
static int ctr_num = 0;

static int nftables_config_counter(oconfig_item_t *ci, const char *instance) {
  ctr_t *list = realloc(ctr_list, (ctr_num + 1) * sizeof(*list));
  if (list == NULL) {
    ERROR("realloc failed: %s", STRERRNO);
    return -1;
  }

  if ((ci->values_num == 0) || (ci->values[0].type != OCONFIG_TYPE_STRING)) {
    ERROR("The `%s' option requires at least one string argument.", ci->key);
    return -1;
  }
  
  size_t display = ci->values_num == 1 ? 0 : 1;

  if (ci->values[display].type != OCONFIG_TYPE_STRING) {
    ERROR("The `%s' option requires a string as argument %d", ci->key, (int)display + 1);
    return -1;
  }

  ctr_list = list;
  ctr_t *counter = ctr_list + ctr_num;

  sstrncpy(counter->counter, ci->values[0].value.string, sizeof(counter->counter));
  sstrncpy(counter->display, ci->values[display].value.string, sizeof(counter->display));
  sstrncpy(counter->instance, instance, sizeof(counter->instance));

  ctr_num++;
  return 0;
}

static int nftables_config(oconfig_item_t *ci) {
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    /* Instance definition */
    if (strcasecmp("Instance", child->key) == 0 && child->children_num) {
      if ((child->values_num == 0) || (child->values[0].type != OCONFIG_TYPE_STRING)) {
        ERROR("Section '%s' cannot be anonymous.", child->key);
        return -1;
      }

      const char *instance = child->values[0].value.string;

      for (int c = 0; c < child->children_num; c++)
        if (nftables_config_counter(child->children + c, instance))
          return -1;
    
    } else  if (strcasecmp("Counter", child->key) == 0) {
      if (nftables_config_counter(child, ""))
        return -1;

    } else {
      ERROR("%s plugin: Unknown config option: %s", PLUGIN_NAME, child->key);
      return 1;

    }
  }

  return 0;
}

static void nftables_dispatch_counter(const char *plugin_instance,
                                     const char *type_instance,
                                     uint64_t bytes, uint64_t packets) {
  value_list_t vl = VALUE_LIST_INIT;
  vl.values_len = 1;

  sstrncpy(vl.plugin, PLUGIN_NAME, sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  sstrncpy(vl.type, "total_bytes", sizeof(vl.type));
  vl.values = &(value_t){.derive = (derive_t)bytes};
  plugin_dispatch_values(&vl);

  sstrncpy(vl.type, "packets", sizeof(vl.type));
  vl.values = &(value_t){.derive = (derive_t)packets};
  plugin_dispatch_values(&vl);
}


static int nftables_read_counter_cb(const struct nlmsghdr *nlh, void *data) {
  struct nftnl_obj *nftnl_counter;

  nftnl_counter = nftnl_obj_alloc();
  if (nftnl_counter == NULL) {
    ERROR("%s plugin: Out of memory", PLUGIN_NAME);
    return MNL_CB_ERROR ;
  }

  if (nftnl_obj_nlmsg_parse(nlh, nftnl_counter) < 0) {
    ERROR("nftables plugin: nftnl_obj_nlmsg_parse failed");
  } else {
    const char *name = nftnl_obj_get_str(nftnl_counter, NFTNL_OBJ_NAME);
    uint64_t bytes = nftnl_obj_get_u64(nftnl_counter, NFTNL_OBJ_CTR_BYTES);
    uint64_t packets = nftnl_obj_get_u64(nftnl_counter, NFTNL_OBJ_CTR_PKTS);

    if (!ctr_num)
      nftables_dispatch_counter("", name, bytes, packets);
    else
      for (ssize_t i = 0; i < ctr_num; i++)
        if (strcasecmp(name, ctr_list[i].counter) == 0)
          nftables_dispatch_counter(ctr_list[i].instance, ctr_list[i].display, bytes, packets);
  }

  nftnl_obj_free(nftnl_counter);
  return MNL_CB_OK;
}

static int nftables_read(void) {
  int ret;
  char buf[MNL_SOCKET_BUFFER_SIZE];

  if (!nlh) {
    struct nftnl_obj *nftnl_ctr_template = nftnl_obj_alloc();
    if (nftnl_ctr_template == NULL) {
      ERROR("nftables plugin: Out of memory");
      return 1;
    }

    nlh_buf = malloc(MNL_SOCKET_BUFFER_SIZE);
    nlh = nftnl_nlmsg_build_hdr(nlh_buf, NFT_MSG_GETOBJ, NFPROTO_UNSPEC, NLM_F_MATCH | NLM_F_ACK, seq);
    nftnl_obj_set_u32(nftnl_ctr_template, NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER);
    nftnl_obj_nlmsg_build_payload(nlh, nftnl_ctr_template);
    nftnl_obj_free(nftnl_ctr_template);
  }

  if (!nl) {
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
      ERROR("nftables plugin: mnl_socket_open failed");
      return -1;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
      ERROR("nftables plugin: mnl_socket_bind failed");
      return -1;
    }

    portid = mnl_socket_get_portid(nl);
  }

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    ERROR("nftables plugin: mnl_socket_send failed");
    mnl_socket_close(nl);
    nl = NULL;
    return -1;
  }

  ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portid, nftables_read_counter_cb, 0);
    if (ret <= 0)
      break;
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }

  if (ret == -1) {
    ERROR("nftables plugin: mnl_socket_recv failed");
    mnl_socket_close(nl);
    nl = NULL;
    return -1;
  }

  return 0;
} /* int nftables_read */

static int nftables_shutdown(void) {
  if (ctr_list)
    free(ctr_list);

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

  seq = time(NULL);
  return 0;
} /* int nftables_init */

void module_register(void) {
  plugin_register_complex_config(PLUGIN_NAME, nftables_config);
  plugin_register_init(PLUGIN_NAME, nftables_init);
  plugin_register_read(PLUGIN_NAME, nftables_read);
  plugin_register_shutdown(PLUGIN_NAME, nftables_shutdown);
}
