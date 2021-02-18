/*
 * service.h
 *
 *  Created on: 17 feb. 2021
 *      Author: Miguel
 */

#ifndef PROCESSING_SERVICE_SERVICE_H_
#define PROCESSING_SERVICE_SERVICE_H_

#include "fsl_crc.h"

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
	uint8_t *request;
} MessageRequest;

typedef struct {
	MessageType type;
	uint8_t *response;
} MessageResponse;

void set_encryption_key(uint8_t key[16], uint8_t iv[16]);

void config_crc(CRC_Type *base, uint32_t polynomial, uint32_t seed);

MessageResponse get_response(MessageRequest *request);
MessageRequest from_packet(uint8_t *buffer, uint32_t length, uint8_t *result);
uint32_t to_packet(MessageResponse *message, uint8_t *buffer);


#endif /* PROCESSING_SERVICE_SERVICE_H_ */
