/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
 
/**
 * \file
 *         This main file is a testing program for the CSM library implemented.
 *         The module implemented are the Symmetrical Block Interface,
 * 		   the Symmetrical Interface and the Mac Interface.
 * 		   This program tests each of the functionality implemented,
 * 		   by printing the result of each function call in the form:
 * 		   <Service>: result
 * 		   where the result is in the format of the AUTOSAR standard
 * 		   In addition, for the encryption/decryption the program prints
 * 		   the ciphertext in exadecimal format and the decrypted text.
 * 		   For the Mac interface, it prints the Mac in hexadecimal format, 
 * 		   and the result of the Mac verification in the format of the
 * 		   AUTOSAR standard.
 *
 * \author
 *         Dario Varano - <dario.varano@ing.unipi.it>
 */

#include "CSM_library.h"

/* Sample function to print results of type Std_ReturnType */
void print_result(Std_ReturnType ret, uint8 *mess){
	if (ret == E_OK)
		printf("%s: E_OK\n", mess);
	else if (ret == E_NOT_OK)
		printf("%s: E_NOT_OK\n", mess);
	else if (ret == CSM_E_BUSY)
		printf("E_NOT_OK\n");
	else 
		printf("%s: CSM_E_SMALL_BUFFER\n", mess);
}
/* Sample function to print results of type Csm_VerifyResultType */
void print_mac_result(Csm_VerifyResultType ret){
	if (ret == CSM_E_VER_OK)
		printf("CSM_E_VER_OK\n");
	else
		printf("CSM_E_VER_NOT_OK\n");
}

int main (void){
	
	Std_ReturnType return_value;

	/* declaration for the structure hosting key data */
	Csm_SymKeyType *keyPtr;
	uint32 decryptedtext_len;
	uint32 ciphertext_len;
	uint32 key_size;
	uint32 block_size;
	uint32 iv_size;
	/* setting key size, iv size and block size */
	iv_size = EVP_MAX_IV_LENGTH;
	key_size = EVP_MAX_KEY_LENGTH;
	block_size = EVP_MAX_BLOCK_LENGTH;
	/* declaration of arrays for key and iv */
	uint8 key[key_size];
	uint8 iv[iv_size];
	/*	create initialization vector	*/
	RAND_bytes(iv, iv_size);
	/*	create key  */
	RAND_bytes(key, key_size);
	/* allocate the structure hosting key data */
	keyPtr = malloc(sizeof(Csm_SymKeyType));
	keyPtr->length = key_size;
	memcpy(keyPtr->data, key, key_size);
	/* Message to be encrypted */
	const uint8 *plaintext = (uint8 *)"In the midway of this our mortal life, I found me in a gloomy wood\0";
	/* ciphertext buffer size (it must be plaintext_size + max_block_size), functions will check the length */
	ciphertext_len = strlen(plaintext)+block_size-1;
	/* ciphertext buffer */
	uint8 ciphertext[ciphertext_len];
	/* Buffer for the decrypted text */
	decryptedtext_len = strlen(plaintext);
	uint8 decryptedtext[decryptedtext_len];

	/* ENCRYPTION AND DECRYPTION */	
	
	/* Encrypt the plaintext */
	return_value = Csm_SymEncryptStart(1, keyPtr, iv, iv_size);
	print_result(return_value, "encrypt start");
	return_value = Csm_SymEncryptUpdate(1, plaintext, strlen(plaintext), ciphertext, &ciphertext_len);
	print_result(return_value, "encrypt update");
	return_value = Csm_SymEncryptFinish(1, ciphertext, &ciphertext_len);
	print_result(return_value, "encrypt finish");
	/* Print the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	const uint8 *ciphered = ciphertext;
	/* Decrypt the ciphertext */
	return_value = Csm_SymDecryptStart(2, keyPtr, iv, iv_size);
	print_result(return_value, "decrypt start");
	return_value = Csm_SymDecryptUpdate(2, ciphered, ciphertext_len, decryptedtext, &decryptedtext_len);
	print_result(return_value, "decrypt update");
	return_value = Csm_SymDecryptFinish(2, decryptedtext, &decryptedtext_len);
	print_result(return_value, "decrypt finish");
	/* Add a NULL terminator */
	decryptedtext[decryptedtext_len] = '\0';
	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);
	
	/* BLOCK ENCRYPTION AND DECRYPTION */

	/* restoring the original ciphertext length */
	ciphertext_len = strlen(plaintext)+block_size-1;

	/* Encrypt the plaintext */
	return_value = Csm_SymBlockEncryptStart(3, keyPtr);
	print_result(return_value, "block encrypt start");
	return_value = Csm_SymBlockEncryptUpdate(3, plaintext, strlen(plaintext), ciphertext, &ciphertext_len);
	print_result(return_value, "block encrypt update");
	return_value = Csm_SymBlockEncryptFinish(3);
	print_result(return_value, "block encrypt finish");
	/* Print the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	const uint8 *ciphered2 = ciphertext;
	/* Decrypt the ciphertext */
	return_value = Csm_SymBlockDecryptStart(4, keyPtr);
	print_result(return_value, "block decrypt start");
	return_value = Csm_SymBlockDecryptUpdate(4, ciphered2, ciphertext_len, decryptedtext, &decryptedtext_len);
	print_result(return_value, "block decrypt update");
	return_value = Csm_SymBlockDecryptFinish(4);
	print_result(return_value, "block decrypt finish");
	/* Add a NULL terminator */
	decryptedtext[decryptedtext_len] = '\0';
	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);

	/* MAC GENERATION AND VERIFICATION */
	
	Csm_VerifyResultType resultPtr;
	uint8 Mac[20];
	/* the following plaintext may be used to check a negative verification */
	uint8 *plaintext2 = "ops, maybe this time it won't be correct...";
	uint32 i;
	uint32 mess_len;
	uint32 mac_len;
	mess_len = strlen(plaintext);
	mac_len = sizeof(Mac);
	/* Mac calculation */
	return_value = Csm_MacGenerateStart(5, keyPtr);
	print_result(return_value, "Mac Generate start");
	return_value = Csm_MacGenerateUpdate(5, plaintext, mess_len);
	print_result(return_value, "Mac Generate update");
	return_value = Csm_MacGenerateFinish(5, Mac, &mac_len, true);
	print_result(return_value, "Mac Generate finish");
	printf("Mac is: ");
	for(i = 0; i < mac_len; i++) 
		printf("%02x", Mac[i]);
	printf("\n");
	/* Mac verification */
	return_value = Csm_MacVerifyStart(6, keyPtr);
	print_result(return_value, "Mac Verify start");
	return_value = Csm_MacVerifyUpdate(6, plaintext, mess_len);
	print_result(return_value, "Mac Verify update");
	return_value = Csm_MacVerifyFinish(6, Mac, mac_len, &resultPtr);
	print_result(return_value, "Mac Verify finish");
	printf("result is:\t");
	print_mac_result(resultPtr);

	/* deallocation of the key structure */
	free(keyPtr);
	return 0;
}
