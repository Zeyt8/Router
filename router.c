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
 * @brief Create a Ethernet Header object
 * 
 * @param sha source ethernet address
 * @param dha destination ethernet address
 * @param type type
 * @return struct ether_header* 
 */
struct ether_header* createEthernetHeader(uint8_t *sha, uint8_t *dha, unsigned short type);

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	packageQueue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */
		
		struct arp_header* arp_hdr = parse_arp(m.payload);
		struct ether_header* ethernet_hdr = (struct ether_header*)m.payload;
		struct icmphdr* icmp_hdr = parse_icmp(m.payload);
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
				continue;
			}
		}
		else
		{

		}
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
}

bool handleARP(packet m, struct arp_header* arp_hdr, struct ether_header* ethernet_hdr)
{
	in_addr_t address = inet_addr(get_interface_ip(m.interface));
	//If request for this router
	if(ntohs(arp_hdr->op) == 1 && arp_hdr->tpa == address)
	{
		uint8_t mac = malloc(sizeof(6));
		get_interface_mac(m.interface, mac);
		struct ether_header* e_h = createEthernetHeader(mac, ethernet_hdr->ether_shost, ethernet_hdr->ether_type);
		end_arp(arp_hdr->spa, arp_hdr->tpa, e_h, m.interface, htons(2));
	}
	else if(ntohs(arp_hdr->op) == 1){
		return false;	//Drop the package
	}
	//If reply
	else if(ntohs(arp_hdr->op) == 2)
	{
		struct arp_entry* arp_e = malloc(sizeof(struct arp_entry));
		arp_e->ip = arp_hdr->spa;
		memcpy(arp_e->mac, ethernet_hdr->ether_shost, 6);
		cons(arp_e, arp_table);
		if(!queue_empty(packageQueue))
		{
			packet* pack = queue_deq(packageQueue);
		}
	}
}

bool handleICMP(packet m, struct icmphdr* icmp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr)
{
	in_addr_t address = inet_addr(get_interface_ip(m.interface));
	if(ip_hdr->daddr == address && icmp_hdr->type == 8)
	{
		send_icmp(ip_hdr->saddr, ip_hdr->daddr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
	}
	else if(ip_hdr->daddr == address)
	{
		return false;	//Drop the package
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

struct ether_header* createEthernetHeader(uint8_t *sha, uint8_t *dha, unsigned short type)
{
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	build_ethhdr(eth_hdr, sha, dha, type);
	return eth_hdr;
}
