
with open('firewall_log.txt', 'r') as file: # firewall log data filepath
    firewall_logs = file.readlines()

# Initialize counters
total_actions = 0
allow_count = 0
block_count = 0
source_ip_counts = {}
threat_category_counts = {"SSH": 0, "DNS": 0, "SQL": 0, "SNMP": 0}  # we can more counters as we want, according to log

# Display the results
for log_entry in firewall_logs:
    # firewall log starts with '# Fields:' which used to initiate the log. had to avoid it
    if log_entry.startswith('# Fields:'):
        continue

    # between each entry there was blank and same pattern, so split() is used.
    fields = log_entry.split()

    
    if len(fields) >= 11:
        # Display capltured info with parsers
        print("Date and Time:", fields[0], fields[1])
        print("Firewall Action:", fields[2])
        print("Protocol:", fields[3])  
        print("Source IP:", fields[4])
        print("Destination IP:", fields[5])
        print("Source Port:", fields[6])
        print("Destination Port:", fields[7])
        print("Size:", fields[8])
        print("TCP Flags:", fields[9])
        print("Infomation:", " ".join(fields[10:]))  # if len(fields) > 10 else "-")
        print("\n")

        # Update counters for allow and block
        total_actions += 1
        if fields[2] == "ALLOW":
            allow_count += 1
        elif fields[2] == "BLOCK":
            block_count += 1

        # checking how many times source ips being captured
        source_ip = fields[4]
        source_ip_counts[source_ip] = source_ip_counts.get(source_ip, 0) + 1

    
        info_field = " ".join(fields[10:])
        if "SSH" in info_field:
            threat_category_counts["SSH"] += 1
        if "DNS" in info_field:
            threat_category_counts["DNS"] += 1
        if "SQL" in info_field:
            threat_category_counts["SQL"] += 1
        if "SNMP" in info_field:
            threat_category_counts["SNMP"] += 1

    else:
        
        print("-------------------------------------------------")

# Display total actions, allow and block counts
print("Total Actions:", total_actions)
print("Allow Actions:", allow_count)
print("Block Actions:", block_count)
print("\n")

# Display source IP analysis
print("Source IP Analysis:")
for source_ip, count in source_ip_counts.items():
    if source_ip != "-": #had to integrate to avoids - entries
     print(f"{source_ip}: {count} times")
print("\n")

# Display threat category analysis
print("Threat Category Analysis:")
for category, count in threat_category_counts.items():
    print(f"{category}: {count} times")
