#include <queue.h>
#include <stdbool.h>
#include "skel.h"
#include "list.h"

list arp_table;
queue packageQueue;

/**
 * @brief Handles an ARP packet
 * 
 * @param m packet to handle
 * @param arp_hdr ARP header of the packet
 * @param ethernet_hdr Ethernet header of the packet
 * @return true: the handling was succesful
 * @return false: drop the package
 */
bool handleARP(packet m, struct arp_header* arp_hdr, struct ether_header* ethernet_hdr);
/**
 * @brief Handles ICMP packet
 * 
 * @param m packet
 * @param icmp_hdr ICMP header of packet
 * @param ip_hdr IP header of packet
 * @param ethernet_hdr Ethernet header of packet
 * @return true: Success
 * @return false: Drop the packet
 */
bool handleICMP(packet m, struct icmphdr* icmp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr);
/**
 * @brief Finds ipv4 address in arp_table if it exists
 * 
 * @param m packet
 * @return struct arp_entry* 
 */
struct arp_entry* checkIfIPv4ExistsInARP(__u32 ip);
/**
 * @brief Checks if ttl and checksum are valid. If not, sends the required icmp error.
 * 
 * @param m packet to check
 * @param ip_header ip header of packet
 * @param ethernet_header ethernet header of packet
 * @return true: ttl and checksum check out
 * @return false: ttl expired or checksum is wrong 
 */
bool checkTTLAndChecksum(packet m, struct iphdr ip_header, struct ether_header ethernet_header);
/**
 * @brief Recalculates checksum if only ttl was decremented
 * 
 * @param ip_hdr 
 * @return uint16_t 
 */
uint16_t ttlDecrementChecksum(struct iphdr* ip_hdr);
/**
 * @brief Get strictest route from table
 * 
 * @param routeTable 
 * @param ip_hdr 
 * @param size Size of route table
 * @return struct route_table_entry* 
 */
struct route_table_entry* getRoute(struct route_table_entry* routeTable, struct iphdr ip_hdr, int size);
/**
 * @brief 
 * 
 * @param payload 
 * @return struct arp_header* The arp header or NULL if it is not an arp packet
 */
struct arp_header* getARPHeader(char *payload);
/**
 * @brief 
 * 
 * @param payload 
 * @return struct icmphdr* The icmp header or null if it is not an icmp packet
 */
struct icmphdr * getICMPHeader(char *payload);
/**
 * @brief Create a Ethernet Header object
 * 
 * @param sha source ethernet address
 * @param dha destination ethernet address
 * @param type type
 * @return struct ether_header* 
 */
struct ether_header* createEthernetHeader(uint8_t *sha, uint8_t *dha, unsigned short type);

/**
 * @brief 
 * 
 * @param daddr destination IP
 * @param saddr source IP
 * @param sha source MAC
 * @param dha destination MAC
 * @param type Type
 * @param code Code
 * @param interface interface 
 * @param id id
 * @param seq sequence
 */
void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq);

/**
 * @brief 
 * 
 * @param daddr destination IP
 * @param saddr source IP
 * @param sha source MAC
 * @param dha destination MAC
 * @param type Type
 * @param code Code
 * @param interface interface 
 */
void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface);

/**
 * @brief 
 * 
 * @param daddr destination IP address
 * @param saddr source IP address
 * @param eth_hdr ethernet header
 * @param interface interface
 * @param arp_op ARP OP: ARPOP_REQUEST or ARPOP_REPLY
 */
void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	packageQueue = queue_create();
	struct route_table_entry* routeTable = malloc(sizeof(struct route_table_entry) * 80000);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		read_rtable(argv[1], routeTable);
		
		struct arp_header* arp_hdr = getARPHeader(m.payload);
		struct ether_header* ethernet_hdr = (struct ether_header*)m.payload;
		struct icmphdr* icmp_hdr = getICMPHeader(m.payload);
		struct iphdr* ip_hdr = (struct iphdr*)(m.payload + sizeof(struct ether_header));

		//If ARP package
		if(arp_hdr != NULL)
		{
			bool success = handleARP(m, arp_hdr, ethernet_hdr);
			if(!success)
			{
				continue;	//Drop the package
			}
		}
		else if(icmp_hdr != NULL)
		{
			bool success = handleICMP(m, icmp_hdr, ip_hdr, ethernet_hdr);
			if(!success)
			{
				continue;	//Drop the package
			}
		}
		else
		{
			bool succes = handleForwarding(routeTable, m, arp_hdr, ip_hdr, ethernet_hdr);
			if(!succes)
			{
				continue;	//Drop the package
			}
		}
		
	}
}

bool handleARP(packet m, struct arp_header* arp_hdr, struct ether_header* ethernet_hdr)
{
	in_addr_t address = inet_addr(get_interface_ip(m.interface));
	//If request for this router
	if(ntohs(arp_hdr->op) == 1 && arp_hdr->tpa == address)	// 1 = arp request
	{
		uint8_t* mac = malloc(sizeof(6));
		get_interface_mac(m.interface, mac);
		struct ether_header* e_h = createEthernetHeader(mac, ethernet_hdr->ether_shost, ethernet_hdr->ether_type);
		send_arp(arp_hdr->spa, arp_hdr->tpa, e_h, m.interface, htons(2));
		free(e_h);
		free(mac);
	}
	else if(ntohs(arp_hdr->op) == 1)
	{
		return false;	//Drop the package
	}
	//If reply
	else if(ntohs(arp_hdr->op) == 2)	// 2 = arp reply
	{
		struct arp_entry* arp_e = malloc(sizeof(struct arp_entry));
		arp_e->ip = arp_hdr->spa;
		memcpy(arp_e->mac, ethernet_hdr->ether_shost, 6);
		cons(arp_e, arp_table);
		if(!queue_empty(packageQueue))
		{
			packet* pack = queue_deq(packageQueue);
			struct ether_header* p_eth_hdr = malloc(sizeof(struct ether_header));
			struct iphdr* p_ip_hdr = malloc(sizeof(struct iphdr));

			if(!checkTTLAndChecksum(m, *p_ip_hdr, *p_eth_hdr)){
				return false;
			}

			p_ip_hdr->ttl--;
            p_ip_hdr->check = ttlDecrementChecksum(p_ip_hdr);

			free(p_eth_hdr);
			free(p_ip_hdr);
		}
		else
		{
			return false;	//Drop the packet
		}
	}
}

bool handleICMP(packet m, struct icmphdr* icmp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr)
{
	in_addr_t address = inet_addr(get_interface_ip(m.interface));
	if(ip_hdr->daddr == address && icmp_hdr->type == 8)	//8 = echo request
	{
		send_icmp(ip_hdr->saddr, ip_hdr->daddr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
	}
	else if(ip_hdr->daddr == address)
	{
		return false;	//Drop the package
	}
}

bool handleForwarding(struct route_table_entry* routeTable, packet m, struct arp_header* arp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr){
	if(!checkTTLAndChecksum(m, *ip_hdr, *ethernet_hdr))
	{
		return false;
	}

	ip_hdr->ttl--;
	ip_hdr->check = ttlDecrementChecksum(ip_hdr);

	struct route_table_entry* route = getRoute(routeTable, *ip_hdr, sizeof(routeTable) / sizeof(struct route_table_entry));

	if(route == NULL)
	{
		send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, 3, 0, m.interface);
		return false;	//Drop packet
	}

	uint8_t* mac = malloc(sizeof(6));
	get_interface_mac(m.interface, mac);

	struct arp_entry* entry = checkIfIPv4ExistsInARP(arp_hdr->tpa);
	if(entry == NULL)
	{
		queue_enq(packageQueue, &m);
		uint8_t macSource = malloc(sizeof(6));
		get_interface_mac(0, macSource);
		uint8_t macDest;
		hwaddr_aton("FF:FF:FF:FF:FF:FF", macDest);
		struct ether_header* eth_hdr = createEthernetHeader(macSource, macDest, 0x806);
	}
	else
	{

	}
}

struct arp_entry* checkIfIPv4ExistsInARP(__u32 ip)
{
	list currentElement = arp_table;
	while(currentElement != NULL)
	{
		if(((struct arp_entry*)currentElement->element)->ip == ip)
		{
			return (struct arp_entry*)currentElement->element;
		}
	}
	return NULL;
}

bool checkTTLAndChecksum(packet m, struct iphdr ip_header, struct ether_header ethernet_header)
{
	if(ip_header.ttl <= 1)
	{
		//Send ttl error
		send_icmp_error(ip_header.saddr, ip_header.daddr, ethernet_header.ether_dhost, ethernet_header.ether_shost, 11, 0, m.interface);
		return false;	//Drop the packet
	}

	__u16 check = ip_header.check;
	ip_header.check = 0;
	ip_header.check = ip_checksum(&ip_header, sizeof(struct iphdr));

	if(check != ip_header.check)
	{
		//Send checksum error

		return false;	//Drop the packet
	}
}

uint16_t ttlDecrementChecksum(struct iphdr* ip_hdr){
	ip_hdr->check = 0;
	return ip_checksum(ip_hdr, sizeof(struct iphdr));
}

struct route_table_entry* getRoute(struct route_table_entry* routeTable, struct iphdr ip_hdr, int length)
{
	int index = -1;
	for(int i = 0; i < length; i++)
	{
		if(ip_hdr.daddr & routeTable[i].mask == routeTable[i].prefix)
		{
			if(index == -1)
			{
				index = i;
			}
			else if(ntohl(routeTable[i].mask) > ntohl(routeTable[index].mask))
			{
				index = i;
			}
		}
	}
	if(index == -1)
	{
		return NULL;
	}
	return &routeTable[index];
} 

struct arp_header* getARPHeader(char *payload)
{
	struct ether_header* eth_hdr;

	eth_hdr = (struct ether_header*)payload;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) 
	{
		struct arp_header* arp_hdr = (struct arp_header*)(payload + sizeof(struct ether_header));
		return arp_hdr;
	} 
	return NULL;
}

struct icmphdr * getICMPHeader(char *payload)
{
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;

	eth_hdr = (struct ether_header*)payload;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) 
	{
		ip_hdr = (struct iphdr *)(payload + sizeof(struct ether_header));
		if (ip_hdr->protocol == 1) 
		{
			struct icmphdr *icmp_hdr = (struct icmphdr *)(payload + sizeof(struct iphdr) + sizeof(struct ether_header));
			return icmp_hdr;
		} 
		return NULL;
	} 
	return NULL;
}

struct ether_header* createEthernetHeader(uint8_t *sha, uint8_t *dha, unsigned short type)
{
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
	return eth_hdr;
}

void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq)
{

	struct ether_header* eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
		.un.echo = {
			.id = id,
			.sequence = seq,
		}
	};
	packet packet;
	void *payload;

	eth_hdr = createEthernetHeader(sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));
	
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	send_packet(&packet);
}

void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface)
{

	struct ether_header* eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
	};
	packet packet;
	void *payload;

	eth_hdr = createEthernetHeader(sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));
	
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	send_packet(&packet);
}

void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op)
{
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arp_op;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	memset(packet.payload, 0, 1600);
	memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	send_packet(&packet);
}
