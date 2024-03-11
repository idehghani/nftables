# Define the main firewall table using the inet family
nft add table inet my_firewall

# Add base chains for input, forward and output (adjust priority as needed)
nft add chain inet my_firewall input { type filter hook input priority 0 \; policy drop \; }
nft add chain inet my_firewall forward { type filter hook forward priority 0 \; policy drop \; }
nft add chain inet my_firewall output { type filter hook output priority 0 \; policy accept \; }

# Add prerouting and postrouting chains for NAT if necessary
nft add chain inet my_firewall prerouting { type nat hook prerouting priority -100 \; }
nft add chain inet my_firewall postrouting { type nat hook postrouting priority 100 \; }

# Create sets to define the different zones
nft add set inet my_firewall zone100 { type ipv4_addr\; flags interval\; }
nft add set inet my_firewall zone200 { type ipv4_addr\; flags interval\; }
nft add set inet my_firewall zone0 { type ipv4_addr\; flags interval\; }

# Populate the sets with the appropriate IP ranges
nft add element inet my_firewall zone100 { 192.168.1.0/24 }
nft add element inet my_firewall zone200 { 192.168.30.0/24 }
nft add element inet my_firewall zone0 { 172.172.172.0/24 }

# Implement the specified rules

# Rule 2: Zone 200 can access Zone 100 with ping and HTTP only
nft add rule inet my_firewall forward ip saddr @zone200 ip daddr @zone100 ip protocol icmp accept
nft add rule inet my_firewall forward ip saddr @zone200 ip daddr @zone100 tcp dport 80 accept

# Rule 3: Zone 200 can access PC1 with ping only
nft add rule inet my_firewall forward ip saddr @zone200 ip daddr @zone0 ip protocol icmp accept

# Rule 4: Zone 100 cannot access Zone 200 except for response traffic
nft add rule inet my_firewall forward ip saddr @zone100 ip daddr @zone200 ct state established,related accept
nft add rule inet my_firewall forward ip saddr @zone100 ip daddr @zone200 drop

# Rule 5: Zone 100 can access PC1 with ping only
nft add rule inet my_firewall forward ip saddr @zone100 ip daddr @zone0 ip protocol icmp accept

# Rule 6: The public host PC1 cannot access Zone 200 except for response traffic
nft add rule inet my_firewall forward ip saddr @zone0 ip daddr @zone200 ct state established,related accept
nft add rule inet my_firewall forward ip saddr @zone0 ip daddr @zone200 drop

# Rule 7: The public host PC1 can access Zone 100 with ping and HTTP through port forwarding
# Note: Adjust 'iifname' to your external interface and the dnat IP to your web server's internal IP
nft add rule inet my_firewall prerouting iifname "eth0" tcp dport 80 dnat to 192.168.1.100:80
nft add rule inet my_firewall forward ip saddr @zone0 ip daddr @zone100 tcp dport 80 accept
