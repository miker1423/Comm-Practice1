/*
 * service.h
 *
 *  Created on: 17 feb. 2021
 *      Author: Miguel
 */

#ifndef PROCESSING_SERVICE_SERVICE_H_
#define PROCESSING_SERVICE_SERVICE_H_

#include "fsl_crc.h"
#include "lwip/api.h"

typedef enum {
	A,
	B,
	C,
	D,
	E,
	F,
	G,
	H
} MessageType;

typedef struct {
	MessageType type;
	const uint8_t *request;
} MessageRequest;

typedef struct {
	MessageType type;
	uint8_t *response;
} MessageResponse;

void set_encryption_key(uint8_t key[16], uint8_t iv[16]);

void config_crc(CRC_Type *base, uint32_t polynomial, uint32_t seed);

struct netconn* start_server(const ip_addr_t *addr, u16_t port);
struct netconn * accept_connection(struct netconn *server);
MessageRequest wait_request(struct netconn *client, uint8_t *result);
MessageResponse get_response(MessageRequest *request);
uint8_t write_response(struct netconn *sender, MessageResponse response);
void close_client(struct netconn *conn);


#endif /* PROCESSING_SERVICE_SERVICE_H_ */
