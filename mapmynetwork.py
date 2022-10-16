import nmap

nm = nmap.PortScanner()

target_ip_addr = input("\nPlease enter IP range to scan (e.g. 192.168.0.1/24): \n")

print("\nScanning "+target_ip_addr+ " ...")

nm.scan(hosts=target_ip_addr, arguments='-sV -O')
# nm.scan(hosts=target_ip_addr, arguments='-sn')

for host in nm.all_hosts():
    print('------------------------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
