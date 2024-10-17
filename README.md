# Packages
- luci-app-fwknock  
Opens tcp ports with a ping or port knocking sequence. Implemented just with nftable rules.  
In case of using TOTP the nftables set holding the codes is updated periodically with a shell script and oathtool
- collectd-mod-nftables  
collectd plugin for collecting statistics from nftables counters
- luci-app-statistics-nftables  
Configuration and Graph definition for Luci statistics
- luci-mod-status-plc
Status page for Qualcom PLC (powerline communication) devices
## Luci statistics plugin
Will be included soon  
The graph definition works already but I still need to write the package and configuration definition
## Collectd nftables plugin
This plugin collects statistics from nftables counters.
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
### nftables rule (anonymous) counters
Local rule counters can be referenced by chain and comment of the rule.  
With nftables there can be several counters in a rule but this plugin only considers the first one for now.
### Plugin confgiuration
An empty configuration section collects all counters, otherwise only listed counters will be collected. Counters can be grouped into instance for creating individual charts. Without a surrounding Instance tag the instance name is empty. If all counters are collected the chain name is used as plugin instance for rule counters and "Named counters" for named counters.
Example: 
```
LoadPlugin nftables
<Plugin nftables>
        <Instance TCP>
                "Counter cnt_reject_from_wan_http" "HTTP"
                "Counter cnt_reject_from_wan_https" "HTTPS"
                "Counter cnt_reject_from_wan_ssh" "SSH"
                "Counter cnt_reject_from_wan_tcp" "Total"
        </Instance>
        <Instance Protocol>
                Counter "cnt_reject_from_wan_udp" "UDP"
                Counter "cnt_reject_from_wan_tcp" "TCP"
                Counter "cnt_reject_from_wan_total" "Total"
        </Instance>
        <Instance WAN>
                Rule "drop_from_wan" "!fw4: drop wan IPv4/IPv6 traffic" "Drop input"
        </Instance>
</Plugin>
```
This can be placed in ```/etc/collectd/conf.d/```. The luci statistics extension will add it automatically into the generated configuration
