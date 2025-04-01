// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

 #include <inttypes.h>
 #include <tee_internal_api.h>
 #include <tee_internal_api_extensions.h>
 #include <acipher_ta.h>
 #include <string.h>
 
 /* 固定的密钥对象ID */
 #define ACIPHER_KEY_ID      "acipher_key"
 #define ACIPHER_KEY_ID_LEN  (sizeof(ACIPHER_KEY_ID) - 1)
 
 struct acipher {
     TEE_ObjectHandle key;
 };
 
 /*
  * 尝试从持久化存储中加载密钥
  */
 static TEE_Result load_persistent_key(struct acipher *state)
 {
     TEE_Result res;
     TEE_ObjectHandle key = TEE_HANDLE_NULL;
 
     res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                    ACIPHER_KEY_ID,
                                    ACIPHER_KEY_ID_LEN,
                                    TEE_DATA_FLAG_ACCESS_READ,
                                    &key);
     if (res == TEE_SUCCESS) {
         state->key = key;
         DMSG("Persistent key loaded successfully");
     } else {
         DMSG("No persistent key found (res=%#" PRIx32 "), will generate one", res);
     }
     return res;
 }
 
 /*
  * 将生成的密钥保存到持久化存储中
  */
 static TEE_Result store_persistent_key(TEE_ObjectHandle key)
 {
     TEE_Result res;
     TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
     uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META |
                            TEE_DATA_FLAG_OVERWRITE;
 
     res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                      ACIPHER_KEY_ID,
                                      ACIPHER_KEY_ID_LEN,
                                      obj_flags,
                                      key,
                                      NULL, 0,
                                      &persistent_key);
     if (res != TEE_SUCCESS) {
         EMSG("TEE_CreatePersistentObject failed: %#" PRIx32, res);
     } else {
         TEE_CloseObject(persistent_key);
     }
     return res;
 }
 
 /*
  * 生成 RSA 密钥对，如果已有持久化密钥则直接加载
  */
 static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
                                TEE_Param params[TEE_NUM_PARAMS])
 {
     TEE_Result res;
     uint32_t key_size;
     TEE_ObjectHandle key;
     const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
     const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE);
 
     if (pt != exp_pt)
         return TEE_ERROR_BAD_PARAMETERS;
 
     key_size = params[0].value.a;
 
     /* 如果已经有持久化密钥，则直接加载 */
     res = load_persistent_key(state);
     if (res == TEE_SUCCESS && state->key != TEE_HANDLE_NULL) {
         DMSG("Persistent key loaded successfully");
         return TEE_SUCCESS;
     }
 
     /* 否则生成新的密钥对 */
     res = TEE_AllocateTransientObject(key_type, key_size, &key);
     if (res) {
         EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32,
              key_type, key_size, res);
         return res;
     }
 
     res = TEE_GenerateKey(key, key_size, NULL, 0);
     if (res) {
         EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key_size, res);
         TEE_FreeTransientObject(key);
         return res;
     }
 
     /* 将生成的密钥保存到持久化存储 */
     res = store_persistent_key(key);
     if (res) {
         EMSG("store_persistent_key failed: %#" PRIx32, res);
         TEE_FreeTransientObject(key);
         return res;
     }
 
     TEE_FreeTransientObject(state->key);
     state->key = key;
     return TEE_SUCCESS;
 }
 
 /* 使用 RSAES_PKCS1_V1_5 算法加密数据 */
 static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
                            TEE_Param params[TEE_NUM_PARAMS])
 {
     TEE_Result res;
     const void *inbuf;
     uint32_t inbuf_len;
     void *outbuf;
     uint32_t outbuf_len;
     TEE_OperationHandle op;
     TEE_ObjectInfo key_info;
     const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
     const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
 
     if (pt != exp_pt)
         return TEE_ERROR_BAD_PARAMETERS;
     if (!state->key)
         return TEE_ERROR_BAD_STATE;
 
     res = TEE_GetObjectInfo1(state->key, &key_info);
     if (res) {
         EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
         return res;
     }
 
     inbuf = params[0].memref.buffer;
     inbuf_len = params[0].memref.size;
     outbuf = params[1].memref.buffer;
     outbuf_len = params[1].memref.size;
 
     res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT, key_info.keySize);
     if (res) {
         EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32,
              alg, key_info.keySize, res);
         return res;
     }
 
     res = TEE_SetOperationKey(op, state->key);
     if (res) {
         EMSG("TEE_SetOperationKey: %#" PRIx32, res);
         goto out;
     }
 
     res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf, &outbuf_len);
     if (res) {
         EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32,
              inbuf_len, params[1].memref.size, res);
     }
     params[1].memref.size = outbuf_len;
 out:
     TEE_FreeOperation(op);
     return res;
 }
 
 /* 使用 RSASSA_PKCS1_V1_5_SHA256 对摘要进行签名 */
 static TEE_Result cmd_sign(struct acipher *state, uint32_t pt,
                             TEE_Param params[TEE_NUM_PARAMS])
 {
     TEE_Result res;
     const void *inbuf;
     uint32_t inbuf_len;
     void *signature;
     uint32_t signature_len;
     TEE_OperationHandle op;
     TEE_ObjectInfo key_info;
     const uint32_t alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
     const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
     if (pt != exp_pt)
         return TEE_ERROR_BAD_PARAMETERS;
     if (!state->key)
         return TEE_ERROR_BAD_STATE;
     res = TEE_GetObjectInfo1(state->key, &key_info);
     if (res) {
         EMSG("TEE_GetObjectInfo1 failed: %#" PRIx32, res);
         return res;
     }
     inbuf = params[0].memref.buffer;
     inbuf_len = params[0].memref.size;
     signature = params[1].memref.buffer;
     signature_len = params[1].memref.size;
     res = TEE_AllocateOperation(&op, alg, TEE_MODE_SIGN, key_info.keySize);
     if (res) {
         EMSG("TEE_AllocateOperation for sign failed: %#" PRIx32, res);
         return res;
     }
     res = TEE_SetOperationKey(op, state->key);
     if (res) {
         EMSG("TEE_SetOperationKey for sign failed: %#" PRIx32, res);
         TEE_FreeOperation(op);
         return res;
     }
     res = TEE_AsymmetricSignDigest(op, NULL, 0, inbuf, inbuf_len, signature, &signature_len);
     if (res) {
         EMSG("TEE_AsymmetricSignDigest failed: %#" PRIx32, res);
     }
     params[1].memref.size = signature_len;
     TEE_FreeOperation(op);
     return res;
 }
 
 /* 使用 RSASSA_PKCS1_V1_5_SHA256 验证签名
  * 修改后：首先计算输入数据的SHA-256摘要，
  * 然后使用该摘要进行签名验证，输出：params[2].value.a 为1表示签名有效，0表示签名无效
  */
 static TEE_Result cmd_verify(struct acipher *state, uint32_t pt,
                                TEE_Param params[TEE_NUM_PARAMS])
 {
     TEE_Result res;
     const void *raw_input;
     uint32_t raw_input_len;
     const void *signature;
     uint32_t signature_len;
     TEE_OperationHandle op = TEE_HANDLE_NULL;
     TEE_ObjectInfo key_info;
     const uint32_t alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
     const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  // 原始输入数据
                                               TEE_PARAM_TYPE_MEMREF_INPUT,  // 签名
                                               TEE_PARAM_TYPE_VALUE_OUTPUT,
                                               TEE_PARAM_TYPE_NONE);
     uint8_t digest[32];
     uint32_t digest_len = sizeof(digest);
     TEE_OperationHandle digest_op = TEE_HANDLE_NULL;
 
     if (pt != exp_pt)
         return TEE_ERROR_BAD_PARAMETERS;
     if (!state->key)
         return TEE_ERROR_BAD_STATE;
 
     res = TEE_GetObjectInfo1(state->key, &key_info);
     if (res) {
         EMSG("TEE_GetObjectInfo1 failed: %#" PRIx32, res);
         return res;
     }
 
     /* 获取原始输入数据 */
     raw_input = params[0].memref.buffer;
     raw_input_len = params[0].memref.size;
     signature = params[1].memref.buffer;
     signature_len = params[1].memref.size;
 
     /* 先计算输入数据的SHA-256摘要 */
     res = TEE_AllocateOperation(&digest_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
     if (res) {
         EMSG("TEE_AllocateOperation for digest failed: %#" PRIx32, res);
         return res;
     }
     res = TEE_DigestDoFinal(digest_op, raw_input, raw_input_len, digest, &digest_len);
     TEE_FreeOperation(digest_op);
     if (res) {
         EMSG("TEE_DigestDoFinal failed: %#" PRIx32, res);
         return res;
     }
 
     /* 使用计算出的摘要进行签名验证 */
     res = TEE_AllocateOperation(&op, alg, TEE_MODE_VERIFY, key_info.keySize);
     if (res) {
         EMSG("TEE_AllocateOperation for verify failed: %#" PRIx32, res);
         return res;
     }
     res = TEE_SetOperationKey(op, state->key);
     if (res) {
         EMSG("TEE_SetOperationKey for verify failed: %#" PRIx32, res);
         TEE_FreeOperation(op);
         return res;
     }
     res = TEE_AsymmetricVerifyDigest(op, NULL, 0, digest, digest_len, signature, signature_len);
     if (res == TEE_SUCCESS) {
         params[2].value.a = 1;
     } else {
         params[2].value.a = 0;
         EMSG("TEE_AsymmetricVerifyDigest failed: %#" PRIx32, res);
     }
     TEE_FreeOperation(op);
     return res;
 }
 
 /* 生成摘要功能：使用 SHA-256 算法
  * 输入：params[0].memref 待计算摘要的数据
  * 输出：params[1].memref 摘要输出（SHA-256 固定32字节）
  */
 static TEE_Result cmd_digest(struct acipher *state, uint32_t pt,
                                TEE_Param params[TEE_NUM_PARAMS])
 {
     (void)state;  /* 未使用 state 参数 */
     TEE_Result res;
     const void *inbuf;
     uint32_t inbuf_len;
     void *digest;
     uint32_t digest_len;
     TEE_OperationHandle op;
     const uint32_t alg = TEE_ALG_SHA256;
     const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
     
     if (pt != exp_pt)
         return TEE_ERROR_BAD_PARAMETERS;
     
     inbuf = params[0].memref.buffer;
     inbuf_len = params[0].memref.size;
     digest = params[1].memref.buffer;
     digest_len = params[1].memref.size;
     
     res = TEE_AllocateOperation(&op, alg, TEE_MODE_DIGEST, 0);
     if (res) {
         EMSG("TEE_AllocateOperation for digest failed: %#" PRIx32, res);
         return res;
     }
     
     res = TEE_DigestDoFinal(op, inbuf, inbuf_len, digest, &digest_len);
     if (res) {
         EMSG("TEE_DigestDoFinal failed: %#" PRIx32, res);
     }
     params[1].memref.size = digest_len;
     
     TEE_FreeOperation(op);
     return res;
 }
 
 TEE_Result TA_CreateEntryPoint(void)
 {
     return TEE_SUCCESS;
 }
 
 void TA_DestroyEntryPoint(void)
 {
 }
 
 TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
                                     TEE_Param __unused params[4],
                                     void **session)
 {
     struct acipher *state = TEE_Malloc(sizeof(*state), 0);
     if (!state)
         return TEE_ERROR_OUT_OF_MEMORY;
     
     state->key = TEE_HANDLE_NULL;
     /* 尝试加载已有持久化密钥，如果加载失败，可在后续调用生成命令 */
     load_persistent_key(state);
     
     *session = state;
     return TEE_SUCCESS;
 }
 
 void TA_CloseSessionEntryPoint(void *session)
 {
     struct acipher *state = session;
     if (state->key != TEE_HANDLE_NULL)
         TEE_FreeTransientObject(state->key);
     TEE_Free(state);
 }
 
 TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
                                       uint32_t param_types,
                                       TEE_Param params[TEE_NUM_PARAMS])
 {
     struct acipher *state = session;
     switch (cmd) {
     case TA_ACIPHER_CMD_GEN_KEY:
         return cmd_gen_key(state, param_types, params);
     case TA_ACIPHER_CMD_ENCRYPT:
         return cmd_enc(state, param_types, params);
     case TA_ACIPHER_CMD_SIGN:
         return cmd_sign(state, param_types, params);
     case TA_ACIPHER_CMD_VERIFY:
         return cmd_verify(state, param_types, params);
     case TA_ACIPHER_CMD_DIGEST:
         return cmd_digest(state, param_types, params);
     default:
         EMSG("Command ID %#" PRIx32 " is not supported", cmd);
         return TEE_ERROR_NOT_SUPPORTED;
     }
 }
 