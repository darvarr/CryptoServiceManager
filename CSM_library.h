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
 *         Definition of the CSM funtions for confidentiality and
 * 		   authentication.
 *
 * \author
 *         Dario Varano - <dario.varano@ing.unipi.it>
 */

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define true 1
#define false 0
#define CSM_SYM_KEY_MAX_SIZE 1024

/*
 * The IDs for the configuration are chosen statically by the programmer and are the following:
 * - Encryption configuration: 			1
 * - Decryption configuration: 			2
 * - Block Encryption configuration: 	3
 * - Block Decryption configuration: 	4
 * - Mac generation configuration: 		5
 * - Mac verification configuration:	6
 * They identifies uniquely the modules
*/
#define ENCRYPT_ID 		1
#define	DECRYPT_ID 		2
#define SYMENCRYPT_ID 	3
#define	SYMDECRYPT_ID 	4
#define MACGEN_ID 		5
#define MACVER_ID 		6

typedef int boolean;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t uint8;
typedef uint16 Csm_ConfigIdType;
typedef uint8 Csm_AlignType; 

/* Structure for storing the key and the initialization vector */
typedef struct Csm_SymKeyType{
	uint32 length;
	Csm_AlignType data[CSM_SYM_KEY_MAX_SIZE];
} Csm_SymKeyType;

/* Enumerator for the return type */
typedef enum Std_ReturnType {
	E_OK,				/* 	Request successful 										*/
	E_NOT_OK,			/* 	Request failed 											*/
	CSM_E_BUSY,			/*	Request failed, CSM service busy						*/
	CSM_E_SMALL_BUFFER	/* 	The provider buffer is too small to store the result 	*/
} Std_ReturnType;

/* Enumerator for the return type of the digest computations */
typedef enum Csm_VerifyResultType {
	CSM_E_VER_OK,				/* 	Verification successful	*/
	CSM_E_VER_NOT_OK			/* 	Verification failed		*/
} Csm_VerifyResultType;

/* Structure for encryption primitive's configuration */
typedef struct Cry_SymEncryptConfigType{
	Csm_ConfigIdType cfgId;
	EVP_CIPHER_CTX *ctx;
	uint32 len;
} Cry_SymEncryptConfigType;

/* Structure for decryption primitive's configuration */
typedef struct Cry_SymDecryptConfigType{
	Csm_ConfigIdType cfgId;
	EVP_CIPHER_CTX *ctx;
	uint32 len;
} Cry_SymDecryptConfigType;

/* Structure for encryption service's configuration */
typedef struct Csm_SymEncryptConfigType{
	Csm_ConfigIdType ConfigId;
	Std_ReturnType (*PrimitiveStartFct)(const void *cfgPtr, const Csm_SymKeyType *keyPtr, 
                     const uint8 *InitVectorPtr, uint32 InitVectorLength);
	Std_ReturnType (*PrimitiveUpdateFct)(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr,	uint32 plainTextLength, 
											uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
	Std_ReturnType (*PrimitiveFinishFct)(Csm_ConfigIdType cfgId, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
	
	void *PrimitiveConfigPtr;
} Csm_SymEncryptConfigType;

/* Structure for decryption service's configuration */
typedef struct Csm_SymDecryptConfigType{
	Csm_ConfigIdType ConfigId;
	Std_ReturnType (*PrimitiveStartFct)(const void *cfgPtr, const Csm_SymKeyType *keyPtr,
                     const uint8 *InitVectorPtr, uint32 InitVectorLength);
	Std_ReturnType (*PrimitiveUpdateFct)(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, uint32 cipherTextLength, 
											uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
	Std_ReturnType (*PrimitiveFinishFct)(Csm_ConfigIdType cfgId, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
	void *PrimitiveConfigPtr;
} Csm_SymDecryptConfigType;

/* Structure for block encryption primitive's configuration */
typedef struct Cry_SymBlockEncryptConfigType{
	Csm_ConfigIdType cfgId;
	EVP_CIPHER_CTX *ctx;
	uint32 len;
	uint32 ciphertext_len;
	uint8 *ciphertext;
	uint32 *cipherTextLengthPtr;
} Cry_SymBlockEncryptConfigType;

/* Structure for block decryption primitive's configuration */
typedef struct Cry_SymBlockDecryptConfigType{
	Csm_ConfigIdType cfgId;
	EVP_CIPHER_CTX *ctx;
	uint32 len;
	uint32 plaintext_len;
	uint8 *plaintext;
	uint32 * plainTextLengthPtr;
} Cry_SymBlockDecryptConfigType;

/* Structure for block encryption service's configuration */
typedef struct Csm_SymBlockEncryptConfigType{
	Csm_ConfigIdType ConfigId;
	Std_ReturnType (*PrimitiveStartFct)(const void *cfgPtr, const Csm_SymKeyType *keyPtr);
	Std_ReturnType (*PrimitiveUpdateFct)(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr,	uint32 plainTextLength, 
											uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
	Std_ReturnType (*PrimitiveFinishFct)(Csm_ConfigIdType cfgId);
	
	void *PrimitiveConfigPtr;
} Csm_SymBlockEncryptConfigType;

/* Structure for block decryption service's configuration */
typedef struct Csm_SymBlockDecryptConfigType{
	Csm_ConfigIdType ConfigId;
	Std_ReturnType (*PrimitiveStartFct)(const void *cfgPtr, const Csm_SymKeyType *keyPtr);
	Std_ReturnType (*PrimitiveUpdateFct)(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, uint32 cipherTextLength, 
											uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
	Std_ReturnType (*PrimitiveFinishFct)(Csm_ConfigIdType cfgId);
	Cry_SymBlockDecryptConfigType *PrimitiveConfigPtr;
} Csm_SymBlockDecryptConfigType;

/* Structure for mac generation primitive's configuration */
typedef struct Cry_MacGenerateConfigType{
	Csm_ConfigIdType cfgId;
	HMAC_CTX ctx;
	uint32 len;
} Cry_MacGenerateConfigType;

/* Structure for mac verification primitive's configuration */
typedef struct Cry_MacVerifyConfigType{
	Csm_ConfigIdType cfgId;	
	HMAC_CTX ctx;
	uint32 len;
	uint8 new_Mac[160];
} Cry_MacVerifyConfigType;

/* Structure for mac generation service's configuration */
typedef struct Csm_MacGenerateConfigType{
	Csm_ConfigIdType ConfigId;
	Std_ReturnType (*PrimitiveStartFct)(const void *cfgId, const Csm_SymKeyType *keyPtr);
	Std_ReturnType (*PrimitiveUpdateFct)(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength);
	Std_ReturnType (*PrimitiveFinishFct)(Csm_ConfigIdType cfgId, uint8 *resultPtr, uint32 *resultLengthPtr, 
									boolean TruncationIsAllowed);
	void *PrimitiveConfigPtr;
} Csm_MacGenerateConfigType;

/* Structure for mac verification service's configuration */
typedef struct Csm_MacVerifyConfigType{
	Csm_ConfigIdType ConfigId;
	Std_ReturnType (*PrimitiveStartFct)(const void *cfgId, const Csm_SymKeyType *keyPtr);
	Std_ReturnType (*PrimitiveUpdateFct)(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength);
	Std_ReturnType (*PrimitiveFinishFct)(Csm_ConfigIdType cfgId, uint8 *MacPtr, uint32 MacLength, Csm_VerifyResultType* resultPtr);
	void *PrimitiveConfigPtr;
} Csm_MacVerifyConfigType;

void OPENSSL_config();

/* ENCRYPTION FUNCTION */

/**
 * @brief It initializes the computation of the cryptographic primitive, so that the primitive is able to process input data.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @param keyPtr is the reference for the initialization vector
 * @param keyPtr is the length of the initializazion vector
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymEncryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr, 
                                   const uint8* InitVectorPtr, uint32 InitVectorLength);
/**
 * @brief It initializes the symmetrical encryption service of the CSM.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @param keyPtr is the reference for the initialization vector
 * @param keyPtr is the length of the initializazion vector
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymEncryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr,
                                   const uint8* InitVectorPtr, uint32 InitVectorLength);
/**
 * @brief It processes a chunk of the given input data with the algorithm of the cryptographic primitive.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param plainTextPtr is the reference for the plaintext to be encrypted
 * @param plainTextLength is the length of the plaintext to be encrypted
 * @param cipherTextPtr is the reference for the output buffer
 * @param cipherTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
/**
 * @brief It feeds the symmetrical encryption service with the input data.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param plainTextPtr is the reference for the plaintext to be encrypted
 * @param plainTextLength is the length of the plaintext to be encrypted
 * @param cipherTextPtr is the reference for the output buffer
 * @param cipherTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
/**
 * @brief It finishes the computation of the cryptographic primitive and store the result into the memory location given.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param keyPtr is the reference for ciphertext buffer
 * @param keyPtr is the reference for the location of memory hosting the length of the ciphertext
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymEncryptFinish(Csm_ConfigIdType cfgId, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
/**
 * @brief It finishes the symmetrical encryption service.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for ciphertext buffer
 * @param keyPtr is the reference for the location of memory hosting the length of the ciphertext
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymEncryptFinish(Csm_ConfigIdType cfgId, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);

/* DECRYPTION FUNCTION */

/**
 * @brief It initializes the computation of the cryptographic primitive, so that the primitive is able to process input data.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @param keyPtr is the reference for the initialization vector
 * @param keyPtr is the length of the initializazion vector
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymDecryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr,
                                   const uint8* InitVectorPtr, uint32 InitVectorLength);
/**
 * @brief It initializes the symmetrical decryption service of the CSM.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @param keyPtr is the reference for the initialization vector
 * @param keyPtr is the length of the initializazion vector
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymDecryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr,
                                   const uint8* InitVectorPtr, uint32 InitVectorLength);
/**
 * @brief It processes a chunk of the given input data with the algorithm of the cryptographic primitive.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param cipherTextPtr is the reference for the ciphertext to be decrypted
 * @param cipherTextLength is the length of the ciphertext to be decrypted
 * @param plainTextPtr is the reference for the output buffer
 * @param plainTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
/**
 * @brief It feeds the symmetrical decryption service with the input data.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param cipherTextPtr is the reference for the ciphertext to be decrypted
 * @param cipherTextLength is the length of the ciphertext to be decrypted
 * @param plainTextPtr is the reference for the output buffer
 * @param plainTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
/**
 * @brief It finishes the computation of the cryptographic primitive and store the result into the memory location given.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param keyPtr is the reference for plaintext buffer
 * @param keyPtr is the reference for the location of memory hosting the length of the plaintext
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymDecryptFinish(Csm_ConfigIdType cfgId, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
/**
 * @brief It finishes the symmetrical decryption service.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for plaintext buffer
 * @param keyPtr is the reference for the location of memory hosting the length of the plaintext
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymDecryptFinish(Csm_ConfigIdType cfgId, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);

/* BLOCK ENCRYPTION FUNCTION */

/**
 * @brief It initializes the computation of the cryptographic primitive, so that the primitive is able to process input data.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymBlockEncryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr);
/**
 * @brief It initializes the symmetrical block encrypt service of the CSM.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymBlockEncryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr);
/**
 * @brief It processes a chunk of the given input data with the algorithm of the cryptographic primitive.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param plainTextPtr is the reference for the plaintext to be encrypted
 * @param plainTextLength is the length of the plaintext to be encrypted
 * @param cipherTextPtr is the reference for the output buffer
 * @param cipherTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymBlockEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
/**
 * @brief It feeds the symmetrical block encryption service with the input data.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param plainTextPtr is the reference for the plaintext to be encrypted
 * @param plainTextLength is the length of the plaintext to be encrypted
 * @param cipherTextPtr is the reference for the output buffer
 * @param cipherTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymBlockEncryptUpdate(Csm_ConfigIdType cfgId, const uint8 *plainTextPtr, 
											uint32 plainTextLength, uint8 *cipherTextPtr, uint32 *cipherTextLengthPtr);
/**
 * @brief It finishes the computation of the cryptographic primitive and store the result into the memory location given.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymBlockEncryptFinish(Csm_ConfigIdType cfgId);
/**
 * @brief It finishes the symmetrical block encryption service.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymBlockEncryptFinish(Csm_ConfigIdType cfgId);

/* BLOCK DECRYPTION FUNCTION */

/**
 * @brief It initializes the computation of the cryptographic primitive, so that the primitive is able to process input data.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymBlockDecryptStart(const void *cfgPtr, const Csm_SymKeyType *keyPtr);
/**
 * @brief It initializes the symmetrical block decrypt service of the CSM.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymBlockDecryptStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr);
/**
 * @brief It processes a chunk of the given input data with the algorithm of the cryptographic primitive.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param cipherTextPtr is the reference for the ciphertext to be decrypted
 * @param cipherTextLength is the length of the ciphertext to be decrypted
 * @param plainTextPtr is the reference for the output buffer
 * @param plainTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymBlockDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
/**
 * @brief It feeds the symmetrical block decryption service with the input data.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param cipherTextPtr is the reference for the ciphertext to be decrypted
 * @param cipherTextLength is the length of the ciphertext to be decrypted
 * @param plainTextPtr is the reference for the output buffer
 * @param plainTextLengthPtr is the reference for the variable hosting the length of the output buffer
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymBlockDecryptUpdate(Csm_ConfigIdType cfgId, const uint8 *cipherTextPtr, 
											uint32 cipherTextLength, uint8 *plainTextPtr, uint32 *plainTextLengthPtr);
/**
 * @brief It finishes the computation of the cryptographic primitive and store the result into the memory location given.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Cry_SymBlockDecryptFinish(Csm_ConfigIdType cfgId);
/**
 * @brief It finishes the symmetrical block decryption service.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @return the result of the encryption computations, of kind Std_ReturnType
 */
Std_ReturnType Csm_SymBlockDecryptFinish(Csm_ConfigIdType cfgId);

/* MAC GENERATION */

/**
 * @brief It initializes the computation of the cryptographic primitive, so that the primitive is able to process input data.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the MAC generation initialization, of kind Std_ReturnType
 */
Std_ReturnType Cry_MacGenerateStart(const void *cfgId, const Csm_SymKeyType *keyPtr);
/**
 * @brief It initializes the MAC generate service of the CSM module.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the MAC generation initialization, of kind Std_ReturnType
 */
Std_ReturnType Csm_MacGenerateStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr);
/**
 * @brief It processes a chunk of the given input data with the algorithm of the cryptographic primitive.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param dataPtr the reference for the input buffer
 * @param dataLength the length for the input buffer
 * @return the result of the MAC calculation, of kind Std_ReturnType
 */
Std_ReturnType Cry_MacGenerateUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength);
/**
 * @brief It feeds the MAC generate service with the input data.
 * 
 * @param cfgId is the identifier to the CSM service configuration
 * @param dataPtr the reference for the input buffer
 * @param dataLength the length for the input buffer
 * @return the result of the MAC calculation, of kind Std_ReturnType
 */
Std_ReturnType Csm_MacGenerateUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength);
/**
 * @brief It finishes the computation of the cryptographic primitive and store the result into the memory location given.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param resultPtr reference to the digest buffer
 * @param resultLengthPtr reference to the mac length
 * @param TruncationIsAllowed is a boolean for the trunction
 * @return the result of the MAC calculation finish, of kind Std_ReturnType
 */
Std_ReturnType Cry_MacGenerateFinish(Csm_ConfigIdType cfgId, uint8 *resultPtr, uint32 *resultLengthPtr, 
										boolean TruncationIsAllowed);
/**
 * @brief It finishes the MAC generation service.
 * 
 * @param cfgPtr is the identifier to the CSM service configuration
 * @param resultPtr reference to the digest buffer
 * @param resultLengthPtr reference to the mac length
 * @param TruncationIsAllowed is a boolean for the trunction
 * @return the result of the MAC calculation finish, of kind Std_ReturnType
 */
Std_ReturnType Csm_MacGenerateFinish(Csm_ConfigIdType cfgId, uint8 *resultPtr, uint32 *resultLengthPtr, boolean TruncationIsAllowed);

/* MAC VERIFICATION */

/**
 * @brief It initializes the computation of the cryptographic primitive, so that the primitive is able to process input data.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the MAC verification initialization, of kind Std_ReturnType
 */
Std_ReturnType Cry_MacVerifyStart(const void *cfgId, const Csm_SymKeyType *keyPtr);
/**
 * @brief It initializes the MAC verify service of the CSM module.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @return the result of the MAC verification initialization, of kind Std_ReturnType
 */
Std_ReturnType Csm_MacVerifyStart(Csm_ConfigIdType cfgId, const Csm_SymKeyType *keyPtr);
/**
 * @brief It processes a chunk of the given input data with the algorithm of the cryptographic primitive.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param dataPtr the reference for the input buffer
 * @param dataLength the length for the input buffer
 * @return the result of the MAC calculation, of kind Std_ReturnType
 */
Std_ReturnType Cry_MacVerifyUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength);
/**
 * @brief feeds the MAC verification service with the input data.
 * 
 * @param cfgId is the identifier of the CSM service configuration
 * @param keyPtr is the reference for the Csm_symKeyType containing the information about the key
 * @param dataPtr the reference for the input buffer
 * @param dataLength the length for the input buffer
 * @return the result of the MAC calculation, of kind Std_ReturnType
 */
Std_ReturnType Csm_MacVerifyUpdate(Csm_ConfigIdType cfgId, const uint8 *dataPtr, uint32 dataLength);
/**
 * @brief It finishes the MAC generation service and verifies the MAC obtained with the one received.
 * 
 * @param cfgPtr is the identifier of the CSM service configuration
 * @param MacPtr reference to the MAC to be verified
 * @param MacLength MAC length
 * @param resultPtr the reference for the result of the MAC comparation
 * @return the result of the MAC calculation finish, of kind Std_ReturnType
 */
Std_ReturnType Cry_MacVerifyFinish(Csm_ConfigIdType cfgId, uint8 *MacPtr, uint32 MacLength, 
										Csm_VerifyResultType *resultPtr);
/**
 * @brief It finishes the MAC generation service and verifies the MAC obtained with the one received.
 * 
 * @param cfgPtr is the identifier to the CSM service configuration
 * @param MacPtr reference to the MAC to be verified
 * @param MacLength MAC length
 * @param resultPtr the reference for the result of the MAC comparation
 * @return the result of the MAC calculation finish, of kind Std_ReturnType
 */
Std_ReturnType Csm_MacVerifyFinish(Csm_ConfigIdType cfgId, uint8 *MacPtr, uint32 MacLength, 
										Csm_VerifyResultType *resultPtr);
