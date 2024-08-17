#!/usr/bin/env python3

import asyncio
from modules.export import export
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

counter = 0
port_list = {
	
    20: "FTP-CLI",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    465: "SMTPS",
    515: "LPD",
    520: "RIP",
    587: "SMTP (Submission)",
    631: "IPP (CUPS)",
    636: "LDAPS",
    873: "rsync",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1024: "Dynamic/Private",
    1080: "Socks Proxy",
    1194: "OpenVPN",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Monitor",
    1521: "Oracle DB",
    1701: "L2TP",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2375: "Docker REST API",
    2376: "Docker REST API (TLS)",
    2483: "Oracle DB",
    2484: "Oracle DB (TLS)",
    3000: "Grafana",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion",
    4443: "HTTPS-Alt",
    4444: "Metasploit",
    4567: "MySQL Group Replication",
    4786: "Cisco Smart Install",
    5060: "SIP",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    6667: "IRC",
    7000: "Couchbase",
    7200: "Hazelcast",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "SonarQube",
    8086: "InfluxDB",
    8088: "Kibana",
    8181: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8444: "Jenkins",
    8888: "HTTP-Alt",
    9000: "SonarQube",
    9090: "Openfire",
    9092: "Kafka",
    9093: "Prometheus Alertmanager",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    9418: "Git",
    9990: "JBoss Management",
    9993: "Unreal Tournament",
    9999: "NMAP",
    10000: "Webmin",
    10050: "Zabbix Agent",
    10051: "Zabbix Server",
    11211: "Memcached",
    11300: "Beanstalkd",
    1521: "Oracle DB",
    25565: "Minecraft",
    27015: "Source Engine Games",
    27017: "MongoDB",
    27018: "MongoDB",
    5044: "Logstash",
    50000: "SAP",
    50030: "Hadoop",
    50070: "Hadoop",
    5555: "Open Remote",
    61616: "ActiveMQ",   
}

async def insert(queue):
	for port in port_list:
		await queue.put(port)


async def consumer(queue, ip_addr, result):
	global counter
	while True:
		port = await queue.get()
		await sock_conn(ip_addr, port, result)
		queue.task_done()
		counter += 1
		print(f'{Y}[!] {C}Scanning : {W}{counter}/{len(port_list)}', end='\r')


async def run(ip_addr, result, threads):
	queue = asyncio.Queue(maxsize=threads)
	distrib = asyncio.create_task(insert(queue))
	workers = [
		asyncio.create_task(
			consumer(queue, ip_addr, result)
		) for _ in range(threads)]

	await asyncio.gather(distrib)
	await queue.join()
	for worker in workers:
		worker.cancel()


def scan(ip_addr, output, data, threads):
    result = {}
    result['ports'] = []
    print(f'\n{Y}[!] Starting Port Scan...{W}\n')
    print(f'{G}[+] {C}Scanning Top 100+ Ports With {threads} Threads...{W}\n')

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run(ip_addr, result, threads))
    loop.close()

    print(f'\n{G}[+] {C}Scan Completed!{W}\n')

    if output != 'None':
        ps_output(output, data, result)
    log_writer('[portscan] Completed')


async def sock_conn(ip_addr, port, result):
    try:
        connector = asyncio.open_connection(ip_addr, port)
        await asyncio.wait_for(connector, 1)
        port_name = port_list[port]  # Get the port name from the port_list dictionary
        print(f'\x1b[K{G}[+] {C}{port} ({port_name}){W}')
        result['ports'].append(f"{port} ({port_name})")
        return True
    except TimeoutError:
        return False
    except Exception:
        pass


def ps_output(output, data, result):
	data['module-Port Scan'] = result
	result.update({'exported': False})
	fname = f'{output["directory"]}/ports.{output["format"]}'
	output['file'] = fname
	export(output, data)
