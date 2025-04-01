// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Your Company
 */

 #ifndef __ACIPHER_TA_H__
 #define __ACIPHER_TA_H__
 
 /* UUID of the acipher example trusted application */
 #define TA_ACIPHER_UUID \
	 { 0xa734eed9, 0xd6a1, 0x4244, { \
		 0xaa, 0x50, 0x7c, 0x99, 0x71, 0x9e, 0x7b, 0x7b } }
 
 /*
  * Command IDs
  */
 #define TA_ACIPHER_CMD_DECRYPT        0
 #define TA_ACIPHER_CMD_VERIFY         1
 
 /*
  * TA_ACIPHER_CMD_DECRYPT
  * in  params[0].memref  input (ciphertext)
  * out params[1].memref  output (plaintext)
  */
 #define TA_ACIPHER_CMD_DECRYPT_PARAMS \
		 (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, \
						  TEE_PARAM_TYPE_MEMREF_OUTPUT, \
						  TEE_PARAM_TYPE_NONE, \
						  TEE_PARAM_TYPE_NONE))
 
 /*
  * TA_ACIPHER_CMD_VERIFY
  * in  params[0].memref  data
  *      params[1].memref  signature
  * out params[2].value.a  result (0: valid, 1: invalid)
  */
 #define TA_ACIPHER_CMD_VERIFY_PARAMS \
		 (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, \
						  TEE_PARAM_TYPE_MEMREF_INPUT, \
						  TEE_PARAM_TYPE_VALUE_OUTPUT, \
						  TEE_PARAM_TYPE_NONE))
 
 #endif /* __ACIPHER_TA_H__ */
 