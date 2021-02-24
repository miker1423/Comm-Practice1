# Reporte práctica 1
#### Autor: Miguel Pérez García

## Descripción del código
---
Estas son las funciones que se implementaron y se exponen como parte de la librería, a continuación explicaré la implementación que e hizo para cada una.

```C
void set_encryption_key(uint8_t key[16], uint8_t iv[16]);

void config_crc(CRC_Type *base, uint32_t polynomial, uint32_t seed);

MessageResponse get_response(MessageRequest *request);
MessageRequest from_packet(uint8_t *buffer, uint32_t length, uint8_t *result);
uint32_t to_packet(MessageResponse *message, uint8_t *buffer);
```

`set_encryption_key`: 
Esta función tiene como única responsabilidad almacenar las llaves que se utilizarán para el cifrado. Existe una función `intit_encryption_context` que es quien interactúa con la librería para configurar el contexto de AES.
```C
void set_encryption_key(uint8_t key[KEY_SIZE], uint8_t iv[KEY_SIZE]){
	memcpy(int_key, key, KEY_SIZE);
	memcpy(int_iv, iv, KEY_SIZE);
}
```

`config_crc`:
Con esta función se configura el CRC en la tarjeta. La función `int_config_crc` es quien configura el periférico como tal, de esta forma las otras funciones pueden utilizar la interna sin tener que estar pasando como parámetro los valores de la semilla y el polinomio.
```C
void config_crc(CRC_Type *base, uint32_t polynomial, uint32_t seed){
	int_polynomial = polynomial;
	int_seed = seed;
	int_config_crc(base);
}
```

`get_response`:

`from_packet`: 
Convierte de un buffer a una estructura que representa a un una petición, además tiene un parámetro para identificar posibles errores en el proceso.
```C
MessageRequest from_packet(uint8_t *buffer, uint32_t length, uint8_t *result){
	CRC_Type *crc = CRC0;
    // Configuramos el CRC0
	int_config_crc(crc);
    // Copiamos la información del buffer sin el CRC al periférico
	CRC_WriteData(crc, buffer, length - 4);
    // Obtenemos el CRC
	uint32_t checksum = CRC_Get32bitResult(CRC0);

    // El CRC está en 4 bytes porque es un entero de 32 bits, por ello necesitamos reconstruirlo
	uint32_t received_checksum = 0;
	int8_t i = 0;
	for(i = 0; i < 4; i++){
		received_checksum |= (uint32_t)(buffer[length - 1 - i] << ((3 - i) * 8));
	}

    // Si no coinciden, regresar con un error
	if(checksum != received_checksum){
		*result = 1;
		MessageRequest temp = { };
		return temp;
	}

    // Ahora desciframos el "cuerpo" del paquete
	size_t len_no_crc = length - 4;
	uint8_t *temp = malloc(len_no_crc * sizeof(uint8_t));
	memcpy(temp, buffer, len_no_crc);
	init_encryption_context();
	AES_CBC_decrypt_buffer(&aes_ctx, temp, len_no_crc);

    // Y convertimos del buffer a la estructura que representa el request
	MessageRequest message = from_decrypted_packet(temp, len_no_crc - 2);
	free(temp);

	*result = 0;
	return message;
}
```

`to_packet`: 
Convierte de una respuesta a un buffer de salida
```C
uint32_t to_packet(MessageResponse *message, uint8_t *buffer){
    // Obtenemos el tamaño en bytes de la respuesta que enviaremos
	uint32_t size = get_message_size(message);
	uint8_t *pre_enc = malloc(size * sizeof(uint8_t));
	memset(pre_enc, 0, size);
    // Convertimos la respuesta a un buffer de bytes
	to_decrypted_packet(message, pre_enc);

    // Le damos padding al buffer porque se requiere que el tamaño sea múltiplo de 16
	uint8_t padded_msg[512] = {0};
	size_t real_size = strlen(pre_enc);
	size_t padded_len = real_size + (16 - (real_size % 16));
	free(pre_enc);

    // Iniciamos el contexto de cifrado
	init_encryption_context();
	AES_CBC_encrypt_buffer(&aes_ctx, padded_msg, padded_len);

    // Iniciamos el CRC
	int_config_crc(CRC0);
	CRC_WriteData(CRC0, padded_msg, padded_len);
    // Acomodamos el CRC en 4 bytes porque es de 32 bits
	uint32_t checksum = CRC_Get32bitResult(CRC0);
	for(size_t i = 0; i < 4; i++)
		padded_msg[padded_len + i] = (uint8_t)(checksum >> (i * 8));

    // Añadimos los 4 bytes que corresponden al CRC
	padded_len += 4;
    // Copiamos al buffer de salida
	memcpy(buffer, padded_msg, padded_len);

    // Regresamos el tamaño total escrito
	return padded_len;
}


```





@startuml

@enduml
