# Packages
- collectd-mod-nftables  
collectd plugin for collecting statistics from nftables counters
- luci-app-statistics-nftables  
Configuration and Graph definition for Luci statistics
## Luci statistics plugin
Will be included soon  
The graph definition works already but I still need to write the package and configuration definition
## Collectd nftables plugin
This plugin collects statistics from nftables counters. Only named counters are supported
### nftables named counters
Named counters are global objects in nftables and can then be referenced rules.
Current named counters can be easily displayed with:
```
nft list counters
```

Example for adding counters in OpenWRT firewall fw4 for reject WAN traffic:
```
nft add counter add counter inet fw4 cnt_reject_from_wan_total
nft add counter add counter inet fw4 cnt_reject_from_wan_http
nft insert rule inet fw4 reject_from_wan counter name cnt_reject_from_wan_total
nft insert rule inet fw4 reject_from_wan tcp dport 80 counter name cnt_reject_from_wan_http
```
### Plugin confgiuration
An empty configuration section collects all counters, otherwise only listed counters will be collected. Counters can be grouped into instance for creating individual charts. Without a surround Instance tag the instance name is empty.  
Example: 
```
LoadPlugin nftables
<Plugin nftables>
        <Instance TCP>
                Counter cnt_reject_from_wan_http HTTP
                Counter cnt_reject_from_wan_https HTTPS
                Counter cnt_reject_from_wan_ssh SSH
                Counter cnt_reject_from_wan_tcp Total
        </Instance>
        <Instance Protocol>
                Counter cnt_reject_from_wan_udp UDP
                Counter cnt_reject_from_wan_tcp TCP
                Counter cnt_reject_from_wan_total Total
        </Instance>
</Plugin>
```
This can be placed in ```/etc/collectd/conf.d/```. The luci statistics extension will add it automatically into the generated configuration
