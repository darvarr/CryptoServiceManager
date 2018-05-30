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
 *         Implementation of the CSM functions for confidentiality and
 * 		   authentication.
 *
 * \author
 *         Dario Varano - <dario.varano@ing.unipi.it>
 */

#include "CSM_library.h"


static Csm_SymEncryptConfigType *csm_encrypt;
static Csm_SymDecryptConfigType *csm_decrypt;
static Csm_SymBlockEncryptConfigType *csm_blockEncrypt;
static Csm_SymBlockDecryptConfigType *csm_blockDecrypt;
static Csm_MacGenerateConfigType *csm_generate;
static Csm_MacVerifyConfigType *csm_verify;

Std_ReturnType Cry_SymEncryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr,
                                   const uint8* InitVectorPtr, uint32 InitVectorLength){
	
	uint32 ret;
	Cry_SymEncryptConfigType *cfg = (Cry_SymEncryptConfigType *)cfgPtr;
	cfg->cfgId = ENCRYPT_ID;
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	cfg->ctx = EVP_CIPHER_CTX_new();
	if(cfg->ctx == NULL){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	/* Initialise the encryption operation */
	ret = EVP_EncryptInit_ex(cfg->ctx, EVP_aes_256_cbc(), NULL, keyPtr->data, InitVectorPtr);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}


Std_ReturnType Csm_SymEncryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr,
                                   const uint8* InitVectorPtr, uint32 InitVectorLength){

	if (csm_encrypt != NULL)
		return CSM_E_BUSY;	
	if (cfgId != ENCRYPT_ID)
		return E_NOT_OK;
	Std_ReturnType return_value;
	csm_encrypt = malloc(sizeof(Csm_SymEncryptConfigType));	
	csm_encrypt->PrimitiveConfigPtr = malloc(sizeof(Cry_SymEncryptConfigType));
	csm_encrypt->ConfigId = ENCRYPT_ID;
	csm_encrypt->PrimitiveStartFct = Cry_SymEncryptStart;
	csm_encrypt->PrimitiveUpdateFct = Cry_SymEncryptUpdate;
	csm_encrypt->PrimitiveFinishFct = Cry_SymEncryptFinish;
	return_value = Cry_SymEncryptStart((const void *)csm_encrypt->PrimitiveConfigPtr, keyPtr, InitVectorPtr, InitVectorLength);
	return return_value;
}

Std_ReturnType Cry_SymEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr){
	if (ENCRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymEncryptConfigType *cfgPtr;
	//uint32 cip_len;
	//cip_len = *cipherTextLengthPtr;
	cfgPtr = csm_encrypt->PrimitiveConfigPtr;
	/* check if the output buffer is large enough */
	if (*cipherTextLengthPtr < plainTextLength+EVP_MAX_BLOCK_LENGTH-1){
		/* Clean up */
		EVP_CIPHER_CTX_free(cfgPtr->ctx);
		EVP_cleanup();
		ERR_free_strings();
		free(csm_encrypt);
		return CSM_E_SMALL_BUFFER;
	}
	uint32 ret;	
	//cfgPtr->ciphertext = cipherTextPtr;
	/* Provide the message to be encrypted, and obtain the encrypted output */
	ret = EVP_EncryptUpdate(cfgPtr->ctx, cipherTextPtr, &cfgPtr->len, plainTextPtr, (int)plainTextLength);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	*cipherTextLengthPtr = cfgPtr->len;
	return E_OK;
}

Std_ReturnType Csm_SymEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr){

	if ((csm_encrypt == NULL) || (csm_encrypt->ConfigId != cfgId))
		return E_NOT_OK;

	if (strlen(plainTextPtr) == 0){
		free(csm_encrypt);
		return E_NOT_OK;
	}
	
	Std_ReturnType return_value;
	return_value = Cry_SymEncryptUpdate(cfgId, plainTextPtr, plainTextLength, 
											cipherTextPtr, cipherTextLengthPtr);
	return return_value;
}

Std_ReturnType Cry_SymEncryptFinish(Csm_ConfigIdType cfgId, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr){

	if (ENCRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymEncryptConfigType *cfgPtr;
	cfgPtr = csm_encrypt->PrimitiveConfigPtr;
	uint32 ret;
	/* Finalise the encryption */
	ret = EVP_EncryptFinal_ex(cfgPtr->ctx, cipherTextPtr + cfgPtr->len, &cfgPtr->len);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	*cipherTextLengthPtr += cfgPtr->len;
	/* Clean up */
	EVP_CIPHER_CTX_free(cfgPtr->ctx);
	EVP_cleanup();
	ERR_free_strings();
	return E_OK;
}

Std_ReturnType Csm_SymEncryptFinish(Csm_ConfigIdType cfgId, uint8* cipherTextPtr, uint32* cipherTextLengthPtr){

	if ((csm_encrypt == NULL) || (csm_encrypt->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_SymEncryptFinish(cfgId, cipherTextPtr, cipherTextLengthPtr);
	free(csm_encrypt);
	return return_value;
}

Std_ReturnType Cry_SymDecryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr,
                                   const uint8* InitVectorPtr, uint32 InitVectorLength){
	
	uint32 ret;
	Cry_SymDecryptConfigType *cfg = (Cry_SymDecryptConfigType *)cfgPtr;
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	/* Create and initialise the context */
	cfg->cfgId = DECRYPT_ID;
	cfg->ctx = EVP_CIPHER_CTX_new();
	if(cfg->ctx == NULL){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	/* Initialise the decryption operation */
	ret = EVP_DecryptInit_ex(cfg->ctx, EVP_aes_256_cbc(), NULL, keyPtr->data, InitVectorPtr);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}

Std_ReturnType Csm_SymDecryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr, 
                                        const uint8* InitVectorPtr, uint32 InitVectorLength){

	if (csm_decrypt != NULL)
		return CSM_E_BUSY;	
	if (cfgId != DECRYPT_ID)
		return E_NOT_OK;
	
	Std_ReturnType return_value;
	csm_decrypt = malloc(sizeof(Csm_SymDecryptConfigType));
	csm_decrypt->PrimitiveConfigPtr = malloc(sizeof(Cry_SymDecryptConfigType));
	csm_decrypt->ConfigId = DECRYPT_ID;
	csm_decrypt->PrimitiveStartFct = Cry_SymDecryptStart;
	csm_decrypt->PrimitiveUpdateFct = Cry_SymDecryptUpdate;
	csm_decrypt->PrimitiveFinishFct = Cry_SymDecryptFinish;
	return_value = Cry_SymDecryptStart((const void*)csm_decrypt->PrimitiveConfigPtr, keyPtr, InitVectorPtr, InitVectorLength);
	return return_value;
}

Std_ReturnType Cry_SymDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr){

	if (DECRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymDecryptConfigType *cfgPtr;
	//uint32 plain_len;
	//plain_len = *plainTextLengthPtr;
	cfgPtr = csm_decrypt->PrimitiveConfigPtr;
	/* check if the output buffer is large enough */
	if (cipherTextLength-EVP_MAX_BLOCK_LENGTH+1 > *plainTextLengthPtr){
		/* Clean up */
		EVP_CIPHER_CTX_free(cfgPtr->ctx);
		EVP_cleanup();
		ERR_free_strings();
		free(csm_decrypt);
		return CSM_E_SMALL_BUFFER;
	}
	uint32 ret;
	//cfgPtr->plaintext = plainTextPtr;
	/* Provide the message to be decrypted, and obtain the plaintext output */
	ret = EVP_DecryptUpdate(cfgPtr->ctx, plainTextPtr, &cfgPtr->len, cipherTextPtr, (int)cipherTextLength);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	//cfgPtr->plainTextLengthPtr = plainTextLengthPtr;
	//cfgPtr->plaintext_len = cfgPtr->len;
	*plainTextLengthPtr = cfgPtr->len;
	return E_OK;
}

Std_ReturnType Csm_SymDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr){

	if ((csm_decrypt == NULL) || (csm_decrypt->ConfigId != cfgId))
		return E_NOT_OK;
	
	if (strlen(cipherTextPtr) == 0){
			free(csm_decrypt);
			return E_NOT_OK;
	}
	
	Std_ReturnType return_value;	
	return_value = Cry_SymDecryptUpdate(cfgId, cipherTextPtr, cipherTextLength, 
											plainTextPtr, plainTextLengthPtr);
	return return_value;
}

Std_ReturnType Cry_SymDecryptFinish(Csm_ConfigIdType cfgId, uint8* plainTextPtr, uint32* plainTextLengthPtr){

	if (DECRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymDecryptConfigType *cfgPtr;
	cfgPtr = csm_decrypt->PrimitiveConfigPtr;
	uint32 ret;
	/* Finalise the decryption. Further plaintext bytes may be written at this stage */
	ret = EVP_DecryptFinal_ex(cfgPtr->ctx, plainTextPtr + cfgPtr->len, &cfgPtr->len);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	//cfgPtr->plaintext_len += cfgPtr->len;
	//*cfgPtr->plainTextLengthPtr = cfgPtr->plaintext_len;
	*plainTextLengthPtr += cfgPtr->len;
	/* Clean up */
	EVP_CIPHER_CTX_free(cfgPtr->ctx);
	EVP_cleanup();
	ERR_free_strings();
	return E_OK;
}

Std_ReturnType Csm_SymDecryptFinish(Csm_ConfigIdType cfgId, uint8* plainTextPtr, uint32* plainTextLengthPtr){

	if ((csm_decrypt == NULL) || (csm_decrypt->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_SymDecryptFinish(cfgId, plainTextPtr, plainTextLengthPtr);
	free(csm_decrypt);
	return return_value;
}

Std_ReturnType Cry_SymBlockEncryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr){
	
	uint32 ret;
	Cry_SymBlockEncryptConfigType *cfg = (Cry_SymBlockEncryptConfigType *)cfgPtr;
	cfg->cfgId = SYMENCRYPT_ID;
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	cfg->ctx = EVP_CIPHER_CTX_new();
	if(cfg->ctx == NULL){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	/* Initialise the encryption operation */
	ret = EVP_EncryptInit_ex(cfg->ctx, EVP_aes_256_ecb(), NULL, keyPtr->data, NULL);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}


Std_ReturnType Csm_SymBlockEncryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr){

	if (csm_blockEncrypt != NULL)
		return CSM_E_BUSY;	
	if (cfgId != SYMENCRYPT_ID)
		return E_NOT_OK;
	Std_ReturnType return_value;
	csm_blockEncrypt = malloc(sizeof(Csm_SymBlockEncryptConfigType));	
	csm_blockEncrypt->PrimitiveConfigPtr = malloc(sizeof(Cry_SymBlockEncryptConfigType));
	csm_blockEncrypt->ConfigId = SYMENCRYPT_ID;
	//csm_blockEncrypt->PrimitiveConfigPtr->cfgId = csm_blockEncrypt->ConfigId;
	csm_blockEncrypt->PrimitiveStartFct = Cry_SymBlockEncryptStart;
	csm_blockEncrypt->PrimitiveUpdateFct = Cry_SymBlockEncryptUpdate;
	csm_blockEncrypt->PrimitiveFinishFct = Cry_SymBlockEncryptFinish;
	return_value = Cry_SymBlockEncryptStart((const void *)csm_blockEncrypt->PrimitiveConfigPtr, keyPtr);
	return return_value;
}

Std_ReturnType Cry_SymBlockEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr){
	if (SYMENCRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymBlockEncryptConfigType *cfgPtr;
	uint32 cip_len;
	cip_len = *cipherTextLengthPtr;
	cfgPtr = csm_blockEncrypt->PrimitiveConfigPtr;
	/* check if the output buffer is large enough */
	if (*cipherTextLengthPtr < plainTextLength+EVP_MAX_BLOCK_LENGTH-1){
		/* Clean up */
		EVP_CIPHER_CTX_free(cfgPtr->ctx);
		EVP_cleanup();
		ERR_free_strings();
		free(csm_blockEncrypt);
		return CSM_E_SMALL_BUFFER;
	}
	uint32 ret;	
	cfgPtr->ciphertext = cipherTextPtr;
	/* Provide the message to be encrypted, and obtain the encrypted output */
	ret = EVP_EncryptUpdate(cfgPtr->ctx, cfgPtr->ciphertext, &cfgPtr->len, plainTextPtr, (int)plainTextLength);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	cfgPtr->ciphertext_len = cfgPtr->len;
	cfgPtr->cipherTextLengthPtr = cipherTextLengthPtr;
	return E_OK;
}

Std_ReturnType Csm_SymBlockEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr){

	if ((csm_blockEncrypt == NULL) || (csm_blockEncrypt->ConfigId != cfgId))
		return E_NOT_OK;

	if (strlen(plainTextPtr) == 0){
		free(csm_blockEncrypt);
		return E_NOT_OK;
	}
	
	Std_ReturnType return_value;
	return_value = Cry_SymBlockEncryptUpdate(cfgId, plainTextPtr, plainTextLength, 
											cipherTextPtr, cipherTextLengthPtr);
	return return_value;
}

Std_ReturnType Cry_SymBlockEncryptFinish(Csm_ConfigIdType cfgId){

	if (SYMENCRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymBlockEncryptConfigType *cfgPtr;
	cfgPtr = csm_blockEncrypt->PrimitiveConfigPtr;
	uint32 ret;
	/* Finalise the encryption */
	ret = EVP_EncryptFinal_ex(cfgPtr->ctx, cfgPtr->ciphertext + cfgPtr->len, &cfgPtr->len);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	cfgPtr->ciphertext_len += cfgPtr->len;
	*cfgPtr->cipherTextLengthPtr = cfgPtr->ciphertext_len;
	/* Clean up */
	EVP_CIPHER_CTX_free(cfgPtr->ctx);
	EVP_cleanup();
	ERR_free_strings();
	return E_OK;
}

Std_ReturnType Csm_SymBlockEncryptFinish(Csm_ConfigIdType cfgId){

	if ((csm_blockEncrypt == NULL) || (csm_blockEncrypt->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_SymBlockEncryptFinish(cfgId);
	free(csm_blockEncrypt);
	return return_value;
}

Std_ReturnType Cry_SymBlockDecryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr){
	
	uint32 ret;
	Cry_SymBlockDecryptConfigType *cfg = (Cry_SymBlockDecryptConfigType *)cfgPtr;
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	/* Create and initialise the context */
	cfg->cfgId = DECRYPT_ID;
	cfg->ctx = EVP_CIPHER_CTX_new();
	if(cfg->ctx == NULL){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	/* Initialise the decryption operation */
	ret = EVP_DecryptInit_ex(cfg->ctx, EVP_aes_256_ecb(), NULL, keyPtr->data, NULL);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}

Std_ReturnType Csm_SymBlockDecryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr){

	if (csm_blockDecrypt != NULL)
		return CSM_E_BUSY;	
	if (cfgId != SYMDECRYPT_ID)
		return E_NOT_OK;
	
	Std_ReturnType return_value;
	csm_blockDecrypt = malloc(sizeof(Csm_SymBlockDecryptConfigType));
	csm_blockDecrypt->PrimitiveConfigPtr = malloc(sizeof(Cry_SymBlockDecryptConfigType));
	csm_blockDecrypt->ConfigId = SYMDECRYPT_ID;
	csm_blockDecrypt->PrimitiveStartFct = Cry_SymBlockDecryptStart;
	csm_blockDecrypt->PrimitiveUpdateFct = Cry_SymBlockDecryptUpdate;
	csm_blockDecrypt->PrimitiveFinishFct = Cry_SymBlockDecryptFinish;
	return_value = Cry_SymBlockDecryptStart((const void*)csm_blockDecrypt->PrimitiveConfigPtr, keyPtr);
	return return_value;
}

Std_ReturnType Cry_SymBlockDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr){

	if (SYMDECRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymBlockDecryptConfigType *cfgPtr;
	uint32 plain_len;
	plain_len = *plainTextLengthPtr;
	cfgPtr = csm_blockDecrypt->PrimitiveConfigPtr;
	/* check if the output buffer is large enough */
	if (cipherTextLength-EVP_MAX_BLOCK_LENGTH+1 > *plainTextLengthPtr){
		/* Clean up */
		EVP_CIPHER_CTX_free(cfgPtr->ctx);
		EVP_cleanup();
		ERR_free_strings();
		free(csm_blockDecrypt);
		return CSM_E_SMALL_BUFFER;
	}
	uint32 ret;
	cfgPtr->plaintext = plainTextPtr;
	/* Provide the message to be decrypted, and obtain the plaintext output */
	ret = EVP_DecryptUpdate(cfgPtr->ctx, cfgPtr->plaintext, &cfgPtr->len, cipherTextPtr, (int)cipherTextLength);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	cfgPtr->plainTextLengthPtr = plainTextLengthPtr;
	cfgPtr->plaintext_len = cfgPtr->len;
	return E_OK;
}

Std_ReturnType Csm_SymBlockDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr){

	if ((csm_blockDecrypt == NULL) || (csm_blockDecrypt->ConfigId != cfgId))
		return E_NOT_OK;
	
	if (strlen(cipherTextPtr) == 0){
			free(csm_blockDecrypt);
			return E_NOT_OK;
	}
	
	Std_ReturnType return_value;	
	return_value = Cry_SymBlockDecryptUpdate(cfgId, cipherTextPtr, cipherTextLength, 
											plainTextPtr, plainTextLengthPtr);
	return return_value;
}

Std_ReturnType Cry_SymBlockDecryptFinish(Csm_ConfigIdType cfgId){

	if (SYMDECRYPT_ID != cfgId)
		return E_NOT_OK;
	Cry_SymBlockDecryptConfigType *cfgPtr;
	cfgPtr = csm_blockDecrypt->PrimitiveConfigPtr;
	uint32 ret;
	/* Finalise the decryption. Further plaintext bytes may be written at this stage */
	ret = EVP_DecryptFinal_ex(cfgPtr->ctx, cfgPtr->plaintext + cfgPtr->len, &cfgPtr->len);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	cfgPtr->plaintext_len += cfgPtr->len;
	*cfgPtr->plainTextLengthPtr = cfgPtr->plaintext_len;
	/* Clean up */
	EVP_CIPHER_CTX_free(cfgPtr->ctx);
	EVP_cleanup();
	ERR_free_strings();
	return E_OK;
}

Std_ReturnType Csm_SymBlockDecryptFinish(Csm_ConfigIdType cfgId){

	if ((csm_blockDecrypt == NULL) || (csm_blockDecrypt->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_SymBlockDecryptFinish(cfgId);
	free(csm_blockDecrypt);
	return return_value;
}

Std_ReturnType Cry_MacGenerateStart(const void *cfgId, const Csm_SymKeyType *keyPtr){

	uint32 ret;
	Cry_MacGenerateConfigType *cfg = (Cry_MacGenerateConfigType *)cfgId;
	cfg->cfgId = MACGEN_ID;
	ret = HMAC_Init(&cfg->ctx, keyPtr->data, keyPtr->length, EVP_sha1());
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}

Std_ReturnType Csm_MacGenerateStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr){

	if (csm_generate != NULL)
		return CSM_E_BUSY;	
	if (cfgId != MACGEN_ID)
		return E_NOT_OK;
	
	Std_ReturnType return_value;
	csm_generate = malloc(sizeof(Csm_MacGenerateConfigType));
	csm_generate->PrimitiveConfigPtr = malloc(sizeof(Cry_MacGenerateConfigType));
	csm_generate->ConfigId = MACGEN_ID;
	csm_generate->PrimitiveStartFct = Cry_MacGenerateStart;
	csm_generate->PrimitiveUpdateFct = Cry_MacGenerateUpdate;
	csm_generate->PrimitiveFinishFct = Cry_MacGenerateFinish;
	return_value = Cry_MacGenerateStart((const void *)csm_generate->PrimitiveConfigPtr, keyPtr);
	return return_value;
}

Std_ReturnType Cry_MacGenerateUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength){

	if (MACGEN_ID != cfgId)
		return E_NOT_OK;
	Cry_MacGenerateConfigType *cfgPtr;
	cfgPtr = csm_generate->PrimitiveConfigPtr;	
	uint32 ret;
	ret = HMAC_Update(&cfgPtr->ctx, dataPtr, dataLength);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}

Std_ReturnType Csm_MacGenerateUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength){

	if ((csm_generate == NULL) || (csm_generate->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_MacGenerateUpdate(cfgId, dataPtr, dataLength);
	return return_value;
}

Std_ReturnType Cry_MacGenerateFinish(Csm_ConfigIdType cfgId, uint8 *resultPtr, uint32 *resultLengthPtr, 
										boolean TruncationIsAllowed){

	if (MACGEN_ID != cfgId)
		return E_NOT_OK;
	Cry_MacGenerateConfigType *cfgPtr;
	cfgPtr = csm_generate->PrimitiveConfigPtr;
	uint8 result_mac[20];
	uint32 ret;
	uint32 res_len;
	res_len = *resultLengthPtr;
	ret = HMAC_Final(&cfgPtr->ctx, result_mac, &cfgPtr->len);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	/*
	/* check if the result buffer is too short to host the result, if it is the case a check of the truncationIsAllowed is required,
	/* if the truncation is permitted, then the Mac is truncated, otherwise an error is returned to the caller
	*/	
	if (res_len < cfgPtr->len){
		if (TruncationIsAllowed == true)
			cfgPtr->len = res_len;
		else{
			/* Clean up */
			HMAC_cleanup(&cfgPtr->ctx);	
			return CSM_E_SMALL_BUFFER;
		}
	}
	*resultLengthPtr = cfgPtr->len;
	memcpy(resultPtr, result_mac, cfgPtr->len);
	/* Clean up */
	HMAC_cleanup(&cfgPtr->ctx);	
	return E_OK;
}

Std_ReturnType Csm_MacGenerateFinish(Csm_ConfigIdType cfgId, uint8 *resultPtr, uint32 *resultLengthPtr, boolean TruncationIsAllowed){

	if ((csm_generate == NULL) || (csm_generate->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_MacGenerateFinish(cfgId, resultPtr, resultLengthPtr, TruncationIsAllowed);
	free(csm_generate);
	return return_value;
}


Std_ReturnType Cry_MacVerifyStart(const void *cfgId, const Csm_SymKeyType *keyPtr){

	uint32 ret;
	Cry_MacVerifyConfigType *cfg = (Cry_MacVerifyConfigType *)cfgId;
	cfg->cfgId = MACVER_ID;
	ret = HMAC_Init(&cfg->ctx, keyPtr->data, keyPtr->length, EVP_sha1());
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}

Std_ReturnType Csm_MacVerifyStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr){

	if (csm_verify != NULL)
		return CSM_E_BUSY;	
	if (cfgId != MACVER_ID)
		return E_NOT_OK;
	
	Std_ReturnType return_value;
	csm_verify = malloc(sizeof(Csm_MacVerifyConfigType));
	csm_verify->PrimitiveConfigPtr = malloc(sizeof(Cry_MacVerifyConfigType));
	csm_verify->ConfigId = MACVER_ID;
	csm_verify->PrimitiveStartFct = Cry_MacVerifyStart;
	csm_verify->PrimitiveUpdateFct = Cry_MacVerifyUpdate;
	csm_verify->PrimitiveFinishFct = Cry_MacVerifyFinish;
	return_value = Cry_MacVerifyStart((const void *)csm_verify->PrimitiveConfigPtr, keyPtr);
	return return_value;
}

Std_ReturnType Cry_MacVerifyUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength){

	if (MACVER_ID != cfgId)
		return E_NOT_OK;
	Cry_MacVerifyConfigType *cfgPtr;
	cfgPtr = csm_verify->PrimitiveConfigPtr;	
	uint32 ret;
	ret = HMAC_Update(&cfgPtr->ctx, dataPtr, dataLength);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	return E_OK;
}

Std_ReturnType Csm_MacVerifyUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength){

	if ((csm_verify == NULL) || (csm_verify->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_MacVerifyUpdate(cfgId, dataPtr, dataLength);
	return return_value;
}

Std_ReturnType Cry_MacVerifyFinish(Csm_ConfigIdType cfgId, uint8 *MacPtr, uint32 MacLength, 
										Csm_VerifyResultType *resultPtr){

	if (MACVER_ID != cfgId)
		return E_NOT_OK;
	Cry_MacVerifyConfigType *cfgPtr;
	cfgPtr = csm_verify->PrimitiveConfigPtr;	
	uint32 res;	
	uint32 ret;
	ret = HMAC_Final(&cfgPtr->ctx, cfgPtr->new_Mac, &cfgPtr->len);
	if(ret != 1){
		ERR_print_errors_fp(stderr);
		return E_NOT_OK;
	}
	if (cfgPtr->len == MacLength)
		res = memcmp(cfgPtr->new_Mac, MacPtr, MacLength);
	if (res == 0)
		*resultPtr = CSM_E_VER_OK;
	else
		*resultPtr = CSM_E_VER_NOT_OK;
	/* Remove key from memory */
	HMAC_cleanup(&cfgPtr->ctx);	
	return E_OK;
}

Std_ReturnType Csm_MacVerifyFinish(Csm_ConfigIdType cfgId, uint8 *MacPtr, uint32 MacLength, 
										Csm_VerifyResultType *resultPtr){

	if ((csm_verify == NULL) || (csm_verify->ConfigId != cfgId))
		return E_NOT_OK;
	Std_ReturnType return_value;
	return_value = Cry_MacVerifyFinish(cfgId, MacPtr, MacLength, resultPtr);
	free(csm_verify);
	return return_value;
}
