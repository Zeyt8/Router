#include <queue.h>
#include <stdbool.h>
#include "skel.h"
#include "list.h"

list arp_table;
queue packageQueue;

/**
 * @brief 
 * 
 * @param m packet
 * @return struct arp_entry* 
 */
struct arp_entry* checkIfIPv4Exists(packet m);

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
		struct arp_entry* entry = checkIfIPv4Exists(m);
		if(entry == NULL){
			queue_enq(packageQueue, &m);
			uint8_t macSource = malloc(sizeof(6));
			get_interface_mac(0, macSource);
			uint8_t macDest;
			hwaddr_aton("FF:FF:FF:FF:FF:FF", macDest);
			struct ether_header* eth_hdr = createEthernetHeader(macSource, macDest, 0x806);
		}
		else{

		}
	}
}

struct arp_entry* checkIfIPv4Exists(packet m)
{
	struct arp_header* header = parse_arp(m.payload);
	list currentElement = arp_table;
	while(currentElement != NULL)
	{
		if(((struct arp_entry*)currentElement->element)->ip == header->tpa)
		{
			return (struct arp_entry*)currentElement->element;
		}
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
