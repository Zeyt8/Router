#include <queue.h>
#include <stdbool.h>
#include "skel.h"
#include "list.h"
#include <stdio.h>

list arp_table = NULL;
queue packageQueue;

/**
 * @brief Handles an ARP packet
 * 
 * @param m packet to handle
 * @param routeTable
 * @param routeTableLength
 * @param arp_hdr ARP header of the packet
 * @param ethernet_hdr Ethernet header of the packet
 * @param icmp_hdr ICMP header of the packet
 * @param ip_header	IP header of the packet
 * @return true: the handling was succesful
 * @return false: drop the package
 */
bool handleARP(packet m, struct route_table_entry* routeTable, size_t routeTableLength, struct arp_header* arp_hdr, struct ether_header* ethernet_hdr, struct icmphdr* icmp_hdr, struct iphdr* ip_header);
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
 * @brief Handles ICMP packet
 * 
 * @param routeTable Route table
 * @param routeTableLength Length of the route table
 * @param m Packet
 * @param arp_hdr ARP header of the packet
 * @param ip_hdr IP header of the packet
 * @param ethernet_hdr Ethernet header of the packet
 * @param icmp_hdr ICMP header of the packet
 * @return true 
 * @return false 
 */
bool handleForwarding(struct route_table_entry* routeTable, size_t routeTableLength, packet m, struct arp_header* arp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr, struct icmphdr* icmp_hdr);
/**
 * @brief Finds ipv4 address in arp_table if it exists
 * 
 * @param ip ip
 * @return struct arp_entry* the entry if it exists, nullptr otherwise
 */
struct arp_entry* checkIfIPv4ExistsInARP(__u32 ip);
/**
 * @brief Checks if ttl and checksum are valid. If not, sends the required icmp error.
 * 
 * @param m packet to check
 * @param ip_header ip header of packet
 * @param ethernet_header ethernet header of packet
 * @param icmp_hdr	ICMP header of the packet
 * @return true: ttl and checksum check out
 * @return false: ttl expired or checksum is wrong 
 */
bool checkTTLAndChecksum(packet m, struct iphdr ip_header, struct ether_header ethernet_header, struct icmphdr* icmp_hdr);
void changeEtherHeader(packet* m,  struct ether_header* eth_hdr);
void changeIPHeader(packet *m, struct iphdr* ip_hdr);
void changeARPHeader(packet *m, struct arp_header* arp_hdr);
/**
 * @brief Recalculates checksum if only ttl was decremented
 * 
 * @param m	Packet
 * @param ip_hdr IP header of the packet
 * @return 
 */
void ttlDecrementChecksum(packet* m, struct iphdr* ip_hdr);
/**
 * @brief Get strictest route from table
 * 
 * @param routeTable Route table
 * @param routeTableLength	Length of the route table
 * @param ip_hdr Ip to search for
 * @return int
 */
int getRoute(struct route_table_entry* routeTable, size_t routeTableLength, struct iphdr ip_hdr);
/**
 * @brief Extracts ARP header of packet
 * 
 * @param payload Packet payload
 * @return struct arp_header* The arp header or NULL if it is not an arp packet
 */
struct arp_header* getARPHeader(char *payload);
/**
 * @brief Extracts ICMP header of packet
 * 
 * @param payload Packet payload
 * @return struct icmphdr* The icmp header or null if it is not an icmp packet
 */
struct icmphdr * getICMPHeader(char *payload);
/**
 * @brief Create a Ethernet Header
 * 
 * @param sha source ethernet address
 * @param dha destination ethernet address
 * @param type type
 * @return struct ether_header* 
 */
struct ether_header* createEthernetHeader(uint8_t *sha, uint8_t *dha, unsigned short type);
/**
 * @brief Create an IP header
 * 
 * @param v 
 * @param ihl 
 * @param tos 
 * @param prot 
 * @param len 
 * @param id 
 * @param frag 
 * @param ttl 
 * @param check 
 * @param daddr 
 * @param saddr 
 * @return struct iphdr* 
 */
struct iphdr* createIPHeader(unsigned int v, unsigned int ihl, uint8_t tos, uint8_t prot, uint16_t len, uint16_t id, uint16_t frag, uint8_t ttl, uint16_t check, uint32_t daddr, uint32_t saddr);
/**
 * @brief Create an ARP header
 * 
 * @param daddr 
 * @param saddr 
 * @param sha 
 * @param tha 
 * @param htype 
 * @param ptype 
 * @param hlen 
 * @param plen 
 * @param op 
 * @return struct arp_header* 
 */
struct arp_header* createARPHeader(uint32_t daddr, u_int32_t saddr, uint8_t* sha, uint8_t* tha, u_int16_t htype, u_int16_t ptype, uint8_t hlen, u_int8_t plen, uint16_t op);
/**
 * @brief Send an icmp packet
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
void sendICMP(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq, bool isError);
/**
 * @brief Send an ARP packet
 * 
 * @param daddr destination IP address
 * @param saddr source IP address
 * @param eth_hdr ethernet header
 * @param interface interface
 * @param arp_op ARP OP: ARPOP_REQUEST or ARPOP_REPLY
 */
void sendARP(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op);

void mergeByPrefix(struct route_table_entry* arr, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;
  
    struct route_table_entry* L, *R;
	L = (struct route_table_entry*)malloc(sizeof(struct route_table_entry) * n1);
	R = (struct route_table_entry*)malloc(sizeof(struct route_table_entry) * n2);
  
    for (i = 0; i < n1; i++)
        L[i] = arr[l + i];
    for (j = 0; j < n2; j++)
        R[j] = arr[m + 1 + j];
  
    i = 0; // Initial index of first subarray
    j = 0; // Initial index of second subarray
    k = l; // Initial index of merged subarray
    while (i < n1 && j < n2) {
        if (L->prefix <= R->prefix) {
            arr[k] = L[i];
            i++;
        }
        else {
            arr[k] = R[j];
            j++;
        }
        k++;
    }
  
    while (i < n1) {
        arr[k] = L[i];
        i++;
        k++;
    }
  
    while (j < n2) {
        arr[k] = R[j];
        j++;
        k++;
    }
}
  
void mergeSortByPrefix(struct route_table_entry* arr, int l, int r)
{
    if (l < r) {
        int m = l + (r - l) / 2;
  
        mergeSortByPrefix(arr, l, m);
        mergeSortByPrefix(arr, m + 1, r);
  
        mergeByPrefix(arr, l, m, r);
    }
}

void mergeByMask(struct route_table_entry* arr, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;
  
    struct route_table_entry* L, *R;
	L = (struct route_table_entry*)malloc(sizeof(struct route_table_entry) * n1);
	R = (struct route_table_entry*)malloc(sizeof(struct route_table_entry) * n2);
  
    for (i = 0; i < n1; i++)
        L[i] = arr[l + i];
    for (j = 0; j < n2; j++)
        R[j] = arr[m + 1 + j];
  
    i = 0; // Initial index of first subarray
    j = 0; // Initial index of second subarray
    k = l; // Initial index of merged subarray
    while (i < n1 && j < n2) {
        if (L->mask >= R->mask) {
            arr[k] = L[i];
            i++;
        }
        else {
            arr[k] = R[j];
            j++;
        }
        k++;
    }
  
    while (i < n1) {
        arr[k] = L[i];
        i++;
        k++;
    }
  
    while (j < n2) {
        arr[k] = R[j];
        j++;
        k++;
    }
}

void mergeSortByMask(struct route_table_entry* arr, int l, int r)
{
    if (l < r) {
        int m = l + (r - l) / 2;
  
        mergeSortByMask(arr, l, m);
        mergeSortByMask(arr, m + 1, r);
  
        mergeByMask(arr, l, m, r);
    }
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	packageQueue = queue_create();
	struct route_table_entry* routeTable = malloc(sizeof(struct route_table_entry) * 80000);
	int routeTableLength = read_rtable(argv[1], routeTable);

	mergeSortByMask(routeTable, 0, routeTableLength - 1);
	mergeSortByPrefix(routeTable, 0, routeTableLength - 1);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */
		struct arp_header* arp_hdr = getARPHeader(m.payload);
		struct ether_header* ethernet_hdr = (struct ether_header*)m.payload;
		struct icmphdr* icmp_hdr = getICMPHeader(m.payload);
		struct iphdr* ip_hdr = (struct iphdr*)(m.payload + sizeof(struct ether_header));

		//If ARP package
		if(arp_hdr != NULL)
		{
			bool success = handleARP(m, routeTable, routeTableLength, arp_hdr, ethernet_hdr, icmp_hdr, ip_hdr);
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
		bool succes = handleForwarding(routeTable, routeTableLength, m, arp_hdr, ip_hdr, ethernet_hdr, icmp_hdr);
		if(!succes)
		{
			continue;	//Drop the package
		}
	}
}

bool handleARP(packet m, struct route_table_entry* routeTable, size_t routeTableLength, struct arp_header* arp_hdr, struct ether_header* ethernet_hdr, struct icmphdr* icmp_hdr, struct iphdr* ip_header)
{
	in_addr_t address = inet_addr(get_interface_ip(m.interface));
	//If request for this router
	if(ntohs(arp_hdr->op) == 1 && arp_hdr->tpa == address)	// 1 = arp request
	{
		uint8_t* mac = (uint8_t*)malloc(sizeof(6));
		get_interface_mac(m.interface, mac);
		struct ether_header* e_h = createEthernetHeader(mac, ethernet_hdr->ether_shost, ethernet_hdr->ether_type);
		sendARP(arp_hdr->spa, arp_hdr->tpa, e_h, m.interface, htons(2));	//2 = arp reply
		free(e_h);
		free(mac);

		return false;
	}
	//If reply
	else if(ntohs(arp_hdr->op) == 2)	// 2 = arp reply
	{
		struct arp_entry* arp_e = malloc(sizeof(struct arp_entry));
		arp_e->ip = arp_hdr->spa;
		memcpy(arp_e->mac, ethernet_hdr->ether_shost, 6);
		arp_table = cons(arp_e, arp_table);
		if(!queue_empty(packageQueue))	//Dequeue queued package if it exists
		{
			packet* pack = queue_deq(packageQueue);
			struct ether_header* p_eth_hdr;
			struct iphdr* p_ip_hdr;

			p_eth_hdr = (struct ether_header*)pack;
			p_ip_hdr = (struct iphdr*)(pack->payload + sizeof(struct ether_header));

			if(!checkTTLAndChecksum(m, *p_ip_hdr, *p_eth_hdr, icmp_hdr))
			{
				return false;
			}

			int index = getRoute(routeTable, routeTableLength, *p_ip_hdr);
			struct route_table_entry route;

			if(index == -1)	//If route not found
			{
				sendICMP(p_ip_hdr->saddr, p_ip_hdr->daddr, p_eth_hdr->ether_dhost, p_eth_hdr->ether_shost, 3, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence, true);
                free(p_eth_hdr);
				free(p_ip_hdr);
				return false;
			}
			else
			{
				route = routeTable[index];
				uint8_t* mac = (uint8_t*)malloc(sizeof(6));
				get_interface_mac(m.interface, mac);

				struct arp_entry* entry = checkIfIPv4ExistsInARP(route.next_hop);

				struct ether_header* header = createEthernetHeader(mac, entry->mac, ethernet_hdr->ether_type);

				changeEtherHeader(&m, ethernet_hdr);

				m.interface = route.interface;

				send_packet(&m);	//Forward

				free(header);
				free(p_eth_hdr);
				free(p_ip_hdr);
				return false;
			}
		}
		else
		{
			return false;	//Drop the packet
		}
	}
	else
	{
		return false;
	}
	return true;
}

bool handleICMP(packet m, struct icmphdr* icmp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr)
{
	if(ip_hdr->ttl <= 1)	//Check ttl
	{
		sendICMP(ip_hdr->saddr, ip_hdr->daddr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, 11, 0, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence, m.interface, true);
		return false;
	}

	//Check checksum
	uint16_t check = icmp_hdr->checksum;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((uint16_t*)icmp_hdr, sizeof(icmp_hdr));

	if(check != icmp_hdr->checksum)
	{
		return false;
	}

	in_addr_t address = inet_addr(get_interface_ip(m.interface));
	if(ip_hdr->daddr == address && icmp_hdr->type == 8)	//8 = echo request
	{
		sendICMP(ip_hdr->saddr, ip_hdr->daddr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence, false);
		return false;
	}
	else if(ip_hdr->daddr == address)
	{
		return false;	//Drop the package
	}
	return true;
}

bool handleForwarding(struct route_table_entry* routeTable, size_t routeTableLength, packet m, struct arp_header* arp_hdr, struct iphdr* ip_hdr, struct ether_header* ethernet_hdr, struct icmphdr* icmp_hdr){
	if(!checkTTLAndChecksum(m, *ip_hdr, *ethernet_hdr, icmp_hdr))
	{
		return false;
	}

	ip_hdr->ttl--;
	ttlDecrementChecksum(&m, ip_hdr);

	int index = getRoute(routeTable, routeTableLength, *ip_hdr);
	struct route_table_entry* route;
	if(index == -1)	//If route does not exist
	{
		sendICMP(ip_hdr->saddr, ip_hdr->daddr, ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, 3, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence, true);
		return false;	//Drop packet
	}
	route = &routeTable[index];

	struct arp_entry* entry = checkIfIPv4ExistsInARP(route->next_hop);
	uint8_t* macSource = (uint8_t*)malloc(sizeof(6));
	get_interface_mac(m.interface, macSource);
	if(entry == NULL)	//If there is no entry in arp_table
	{
		queue_enq(packageQueue, &m);
		uint8_t* macDest = (uint8_t*)malloc(sizeof(6));
		hwaddr_aton("FF:FF:FF:FF:FF:FF", macDest);
		struct ether_header* eth_hdr = createEthernetHeader(macSource, macDest, htons(0x806));

		sendARP(route->next_hop, inet_addr(get_interface_ip(route->interface)), eth_hdr, route->interface, htons(1));	// 1 = arp request

		free(macSource);
		free(macDest);
		free(eth_hdr);
		return false;
	}
	else
	{
		struct ether_header* eth_hdr = createEthernetHeader(macSource, entry->mac, ethernet_hdr->ether_type);
		changeEtherHeader(&m, eth_hdr);
		(&m)->interface = route->interface;

		send_packet(&m);	//Forward
		free(eth_hdr);
	}
	return true;
}

struct arp_entry* checkIfIPv4ExistsInARP(uint32_t ip)
{
	list currentElement = arp_table;
	while(currentElement != NULL)
	{
		if(((struct arp_entry*)currentElement->element)->ip == ip)
		{
			return (struct arp_entry*)currentElement->element;
		}
		currentElement = currentElement->next;
	}
	return NULL;
}

bool checkTTLAndChecksum(packet m, struct iphdr ip_header, struct ether_header ethernet_header, struct icmphdr* icmp_hdr)
{
	if(ip_header.ttl <= 1)
	{
		//Send ttl error
		sendICMP(ip_header.saddr, ip_header.daddr, ethernet_header.ether_dhost, ethernet_header.ether_shost, 11, 0, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence, m.interface, true);
		return false;	//Drop the packet
	}
	__u16 check = ip_header.check;
	ip_header.check = 0;
	ip_header.check = ip_checksum((uint8_t*)&ip_header, sizeof(struct iphdr));

	if(check != ip_header.check)
	{
		return false;	//Drop the packet
	}
	return true;
}

void ttlDecrementChecksum(packet* m, struct iphdr* ip_hdr)
{
	//ip_hdr->check = 0;
	//ip_hdr->check = ip_checksum((uint8_t*)ip_hdr, sizeof(struct iphdr));
	uint16_t oldCheck = ip_hdr->check;
	uint8_t currTTL = ip_hdr->ttl;
	uint8_t oldTTL = currTTL + 1;
	uint16_t newCheck = ~(~oldCheck + (-oldTTL) + currTTL);
	ip_hdr->check = newCheck;
	changeIPHeader(m, ip_hdr);
}

void changeEtherHeader(packet* m,  struct ether_header* eth_hdr)
{
	memcpy(m->payload, eth_hdr, sizeof(struct ether_header));
}

void changeIPHeader(packet *m, struct iphdr* ip_hdr)
{
	memcpy(m->payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
}

void changeARPHeader(packet *m, struct arp_header* arp_hdr)
{
	memcpy(m->payload + sizeof(struct ethhdr), arp_hdr, sizeof(struct arp_header));
}

int getRoute(struct route_table_entry* routeTable, size_t routeTableLength, struct iphdr ip_hdr)
{
	/*int l = 0;
	int r = routeTableLength - 1;
	while(l <= r)
	{
		int mid = l + (r - l) / 2;
		if(routeTable[mid].prefix == (ip_hdr.daddr & routeTable[mid].mask))
		{
			return mid;
		}
		else if(ip_hdr.daddr > routeTable[mid].prefix)
		{
			l = mid + 1;
		}
		else
		{
			r = mid - 1;
		}
	}
	return -1;*/
	int index = -1;
	uint32_t biggestMask = 0;
	for(int i=0;i<routeTableLength;i++)
	{
		if((ip_hdr.daddr & routeTable[i].mask) == routeTable[i].prefix)
		{
			if(routeTable[i].mask > biggestMask)
			{
				index = i;
				biggestMask = routeTable[i].mask;
			}
		}
	}
	return index;
} 

struct arp_header* getARPHeader(char *payload)
{
	struct ether_header* eth_hdr;

	eth_hdr = (struct ether_header*)payload;
	if (ntohs(eth_hdr->ether_type) == 0x0806)
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
	if (ntohs(eth_hdr->ether_type) == 0x0800)
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
	struct ether_header* eth_hdr = (struct ether_header*)malloc(sizeof(struct ether_header));
	memcpy(eth_hdr->ether_shost, sha, 6);
	memcpy(eth_hdr->ether_dhost, dha, 6);
	eth_hdr->ether_type = type;
	return eth_hdr;
}

struct iphdr* createIPHeader(unsigned int v, unsigned int ihl, uint8_t tos, uint8_t prot, uint16_t len, uint16_t id, uint16_t frag, uint8_t ttl, uint16_t check, uint32_t daddr, uint32_t saddr)
{
	struct iphdr* ip_hdr = (struct iphdr*)malloc(sizeof(struct iphdr));
	ip_hdr->version = v;
	ip_hdr->ihl = ihl;
	ip_hdr->tos = tos;
	ip_hdr->protocol = prot;
	ip_hdr->tot_len = len;
	ip_hdr->id = id;
	ip_hdr->frag_off = frag;
	ip_hdr->ttl = ttl;
	ip_hdr->check = check;
	ip_hdr->daddr = daddr;
	ip_hdr->saddr = saddr;

	return ip_hdr;
}

struct arp_header* createARPHeader(uint32_t daddr, u_int32_t saddr, uint8_t* sha, uint8_t* tha, u_int16_t htype, u_int16_t ptype, uint8_t hlen, u_int8_t plen, uint16_t op)
{
	struct arp_header* arp_hdr = (struct arp_header*)malloc(sizeof(struct arp_header));
	arp_hdr->tpa = daddr;
	arp_hdr->spa = saddr;
	memcpy(arp_hdr->sha, sha, 6);
	memcpy(arp_hdr->tha, tha, 6);
	arp_hdr->htype = htype;
	arp_hdr->ptype = ptype;
	arp_hdr->op = op;
	arp_hdr->hlen = hlen;
	arp_hdr->plen = plen;

	return arp_hdr;
}

void sendICMP(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq, bool isError)
{

	struct ether_header* eth_hdr;
	struct iphdr* ip_hdr;
	struct icmphdr icmp_hdr;
	icmp_hdr.type = type;
	icmp_hdr.code = code;
	icmp_hdr.checksum = 0;
	if(!isError)
	{
		icmp_hdr.un.echo.id = id;
		icmp_hdr.un.echo.sequence = seq;
	}
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	packet packet;

	eth_hdr = createEthernetHeader(sha, dha, htons(0x0800));

	ip_hdr = createIPHeader(4, 5, 0, IPPROTO_ICMP, htons(sizeof(struct iphdr) + sizeof(struct icmphdr)), htons(1), 0, 64, 0, daddr, saddr);
	ip_hdr->check = ip_checksum((uint8_t*)ip_hdr, sizeof(struct iphdr));
	
	packet.interface = interface;	
	changeEtherHeader(&packet, eth_hdr);
	changeIPHeader(&packet, ip_hdr);
	memcpy(packet.payload  + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	send_packet(&packet);
	free(eth_hdr);
}

void sendARP(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op)
{
	struct arp_header* arp_hdr;
	packet packet;

	arp_hdr = createARPHeader(daddr, saddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, htons(1), htons(0x0800), 6, 4, arp_op);
	packet.interface = interface;
	memset(packet.payload, 0, 1600);
	changeEtherHeader(&packet, eth_hdr);
	changeARPHeader(&packet, arp_hdr);
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);

	send_packet(&packet);
}
