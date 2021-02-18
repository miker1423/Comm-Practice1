/*
 * service.c
 *
 *  Created on: 17 feb. 2021
 *      Author: Miguel
 */
#include "service.h"
#include "aes.h"

#define KEY_SIZE 16
#define ENUM_START_CHAR 65


struct AES_ctx aes_ctx;
uint8_t int_key[KEY_SIZE];
uint8_t int_iv[KEY_SIZE];
uint32_t int_polynomial;
uint32_t int_seed;


void init_encryption_context(){
	AES_init_ctx_iv(&aes_ctx, int_key, int_iv);
}

void set_encryption_key(uint8_t key[KEY_SIZE], uint8_t iv[KEY_SIZE]){
	memcpy(int_key, key, KEY_SIZE);
	memcpy(int_iv, iv, KEY_SIZE);

	init_encryption_context();
}

void int_config_crc(CRC_Type *base){
    crc_config_t config;

    config.polynomial         = int_polynomial;
    config.seed               = int_seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

void config_crc(CRC_Type *base, uint32_t polynomial, uint32_t seed){
	int_polynomial = polynomial;
	int_seed = seed;
	int_config_crc(base);
}

MessageResponse get_response(MessageRequest *request) {
	MessageResponse response = {
			.type = request->type
	};
	switch(request->type){
		case A: { response.response = "This is response to A"; break; }
		case B: { response.response = "This is response to B"; break; }
		case C: { response.response = "This is response to C"; break; }
		case D: { response.response = "This is response to D"; break; }
		case E: { response.response = "This is response to E"; break; }
		case F: { response.response = "This is response to F"; break; }
		case G: { response.response = "This is response to G"; break; }
		case H: { response.response = "This is response to H"; break; }
	}

	return response;
}

MessageRequest from_decrypted_packet(uint8_t *buffer, uint32_t size) {
	MessageRequest message = {};
	message.type = (MessageType)(buffer[0] - ENUM_START_CHAR);
	message.request = malloc(size * sizeof(uint8_t));
	memcpy(message.request, buffer + 2, size);
	return message;
}

MessageRequest from_packet(uint8_t *buffer, uint32_t length, uint8_t *result){
	CRC_Type *crc = CRC0;
	int_config_crc(crc);
	CRC_WriteData(crc, buffer, length - 4);
	uint32_t checksum = CRC_Get32bitResult(CRC0);

	uint32_t received_checksum = 0;
	int8_t i = 0;
	for(i = 0; i < 4; i++){
		received_checksum |= (uint32_t)(buffer[length - 1 - i] << ((3 - i) * 8));
	}

	if(checksum != received_checksum){
		*result = 1;
		MessageRequest temp = { };
		return temp;
	}

	size_t len_no_crc = length - 4;
	uint8_t *temp = malloc(len_no_crc * sizeof(uint8_t));
	memcpy(temp, buffer, len_no_crc);
	init_encryption_context();
	AES_CBC_decrypt_buffer(&aes_ctx, temp, len_no_crc);

	MessageRequest message = from_decrypted_packet(temp, len_no_crc - 2);
	free(temp);

	*result = 0;
	return message;
}

void to_decrypted_packet(MessageResponse *response, uint8_t *buffer) {
	size_t str_length = strlen(response->response);
	buffer[0] = (uint8_t)(response->type) + ENUM_START_CHAR;
	buffer[1] = (uint8_t)0x2C;
	memcpy(buffer + 2, response->response, str_length);
}

uint32_t get_message_size(MessageResponse *response){
	size_t str_length = strlen(response->response);
	return 2 + str_length;
}

uint32_t to_packet(MessageResponse *message, uint8_t *buffer){
	uint32_t size = get_message_size(message);
	uint8_t *pre_enc = malloc(size * sizeof(uint8_t));
	memset(pre_enc, 0, size);
	to_decrypted_packet(message, pre_enc);

	uint8_t padded_msg[512] = {0};
	size_t real_size = strlen(pre_enc);
	size_t padded_len = real_size + (16 - (real_size % 16));
	free(pre_enc);

	init_encryption_context();
	AES_CBC_encrypt_buffer(&aes_ctx, padded_msg, padded_len);
	int_config_crc(CRC0);
	CRC_WriteData(CRC0, padded_msg, padded_len);
	uint32_t checksum = CRC_Get32bitResult(CRC0);
	for(size_t i = 0; i < 4; i++)
		padded_msg[padded_len + i] = (uint8_t)(checksum >> (i * 8));

	padded_len += 4;
	memcpy(buffer, padded_msg, padded_len);

	return padded_len;
}

