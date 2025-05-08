/*
 * merged_ta.c
 *
 * Combined TA: OCRAM Load, AES ciphering, and ACIPHER RSA functionalities
 *
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2018, Linaro Limited
 */

 #include <inttypes.h>
 #include <tee_internal_api.h>
 #include <tee_internal_api_extensions.h>
 #include <string.h>
 #include <stdlib.h>
 #include "ocram_load_ta.h" /* merged header with OCRAM, AES, and ACIPHER macros */
 
 /* Constants for OCRAM PTA commands and UUIDs */
 #define MODEL_DATA_OBJ_ID     "model_data.bin"
 #define OCRAM_LOAD_CMD        0
 #define OCRAM_READ_CMD        0
 static const TEE_UUID pta_ocram_load_uuid = {
     0xd9e00de1, 0x950b, 0x4eb8,
     { 0xb7, 0xd1, 0x6b, 0x32, 0xde, 0xec, 0x18, 0x57 }
 };
 static const TEE_UUID pta_ocram_read_uuid = {
     0xfa152bfd, 0x7c9e, 0x4c33,
     { 0xb8, 0xac, 0x7f, 0x5c, 0x2b, 0x64, 0x49, 0x92 }
 };
 
 /* AES definitions */
 #define AES128_KEY_BIT_SIZE    128
 #define AES128_KEY_BYTE_SIZE   (AES128_KEY_BIT_SIZE / 8)
 #define AES256_KEY_BIT_SIZE    256
 #define AES256_KEY_BYTE_SIZE   (AES256_KEY_BIT_SIZE / 8)
 
 /* ACIPHER definitions */
 #define ACIPHER_KEY_ID         "acipher_key"
 #define ACIPHER_KEY_ID_LEN     (sizeof(ACIPHER_KEY_ID) - 1)
 
 /* AES cipher context per session */
 struct aes_cipher {
     uint32_t algo;
     uint32_t mode;
     uint32_t key_size;
     TEE_OperationHandle op_handle;
     TEE_ObjectHandle key_handle;
 };
 
 /* ACIPHER context per session */
 struct acipher {
     TEE_ObjectHandle key;
 };
 
 /* Combined session context */
 struct ta_ctx {
     struct aes_cipher aes;
     struct acipher aci;
 };
 
 /* Forward declarations for AES helpers */
 static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo);
 static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size);
 static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode);
 static TEE_Result alloc_resources(struct aes_cipher *sess,
                                   uint32_t param_types,
                                   TEE_Param params[4]);
 static TEE_Result set_aes_key(struct aes_cipher *sess,
                               uint32_t param_types,
                               TEE_Param params[4]);
 static TEE_Result reset_aes_iv(struct aes_cipher *sess,
                                uint32_t param_types,
                                TEE_Param params[4]);
 static TEE_Result cipher_buffer(struct aes_cipher *sess,
                                 uint32_t param_types,
                                 TEE_Param params[4]);
 
 /* Forward declarations for ACIPHER helpers */
 static TEE_Result load_persistent_key(struct acipher *state);
 static TEE_Result store_persistent_key(TEE_ObjectHandle key);
 static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
                               TEE_Param params[TEE_NUM_PARAMS]);
 static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
                           TEE_Param params[TEE_NUM_PARAMS]);
 static TEE_Result cmd_sign(struct acipher *state, uint32_t pt,
                            TEE_Param params[TEE_NUM_PARAMS]);
 static TEE_Result cmd_verify(struct acipher *state, uint32_t pt,
                              TEE_Param params[TEE_NUM_PARAMS]);
 static TEE_Result cmd_digest(struct acipher *state, uint32_t pt,
                              TEE_Param params[TEE_NUM_PARAMS]);
 
 /*----------------------------------------------------------
  * AES helper implementations (from optee_examples/aes/ta)
  *---------------------------------------------------------*/
 static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
 {
     switch (param) {
     case TA_AES_ALGO_ECB:
         *algo = TEE_ALG_AES_ECB_NOPAD;
         return TEE_SUCCESS;
     case TA_AES_ALGO_CBC:
         *algo = TEE_ALG_AES_CBC_NOPAD;
         return TEE_SUCCESS;
     case TA_AES_ALGO_CTR:
         *algo = TEE_ALG_AES_CTR;
         return TEE_SUCCESS;
     default:
         EMSG("Invalid AES algo %u", param);
         return TEE_ERROR_BAD_PARAMETERS;
     }
 }
 
 static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
 {
     switch (param) {
     case AES128_KEY_BYTE_SIZE:
     case AES256_KEY_BYTE_SIZE:
         *key_size = param;
         return TEE_SUCCESS;
     default:
         EMSG("Invalid AES key size %u", param);
         return TEE_ERROR_BAD_PARAMETERS;
     }
 }
 
 static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
 {
     switch (param) {
     case TA_AES_MODE_ENCODE:
         *mode = TEE_MODE_ENCRYPT;
         return TEE_SUCCESS;
     case TA_AES_MODE_DECODE:
         *mode = TEE_MODE_DECRYPT;
         return TEE_SUCCESS;
     default:
         EMSG("Invalid AES mode %u", param);
         return TEE_ERROR_BAD_PARAMETERS;
     }
 }
 
 static TEE_Result alloc_resources(struct aes_cipher *sess,
                                   uint32_t param_types,
                                   TEE_Param params[4])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_VALUE_INPUT,
         TEE_PARAM_TYPE_VALUE_INPUT,
         TEE_PARAM_TYPE_VALUE_INPUT,
         TEE_PARAM_TYPE_NONE);
     if (param_types != exp)
         return TEE_ERROR_BAD_PARAMETERS;
 
     TEE_Result res;
     res = ta2tee_algo_id(params[0].value.a, &sess->algo);
     if (res != TEE_SUCCESS) return res;
     res = ta2tee_key_size(params[1].value.a, &sess->key_size);
     if (res != TEE_SUCCESS) return res;
     res = ta2tee_mode_id(params[2].value.a, &sess->mode);
     if (res != TEE_SUCCESS) return res;
 
     if (sess->op_handle != TEE_HANDLE_NULL)
         TEE_FreeOperation(sess->op_handle);
     if (sess->key_handle != TEE_HANDLE_NULL)
         TEE_FreeTransientObject(sess->key_handle);
 
     res = TEE_AllocateOperation(&sess->op_handle,
                                 sess->algo,
                                 sess->mode,
                                 sess->key_size * 8);
     if (res != TEE_SUCCESS) {
         sess->op_handle = TEE_HANDLE_NULL;
         return res;
     }
     res = TEE_AllocateTransientObject(TEE_TYPE_AES,
                                       sess->key_size * 8,
                                       &sess->key_handle);
     if (res != TEE_SUCCESS) {
         TEE_FreeOperation(sess->op_handle);
         sess->op_handle = TEE_HANDLE_NULL;
         sess->key_handle = TEE_HANDLE_NULL;
         return res;
     }
 
     void *dummy = TEE_Malloc(sess->key_size, 0);
     if (!dummy)
         return TEE_ERROR_OUT_OF_MEMORY;
     {
         TEE_Attribute attr;
         TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                              dummy, sess->key_size);
         res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
     }
     TEE_Free(dummy);
     if (res != TEE_SUCCESS)
         return res;
 
     return TEE_SetOperationKey(sess->op_handle, sess->key_handle);
 }
 
 static TEE_Result set_aes_key(struct aes_cipher *sess,
                               uint32_t param_types,
                               TEE_Param params[4])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE);
     if (param_types != exp)
         return TEE_ERROR_BAD_PARAMETERS;
 
     uint32_t key_sz = params[0].memref.size;
     if (key_sz != sess->key_size)
         return TEE_ERROR_BAD_PARAMETERS;
 
     TEE_Attribute attr;
     TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                          params[0].memref.buffer,
                          key_sz);
 
     TEE_ResetTransientObject(sess->key_handle);
     TEE_Result res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
     if (res != TEE_SUCCESS)
         return res;
 
     TEE_ResetOperation(sess->op_handle);
     return TEE_SetOperationKey(sess->op_handle, sess->key_handle);
 }
 
 static TEE_Result reset_aes_iv(struct aes_cipher *sess,
                                uint32_t param_types,
                                TEE_Param params[4])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE);
     if (param_types != exp)
         return TEE_ERROR_BAD_PARAMETERS;
 
     TEE_CipherInit(sess->op_handle,
                    params[0].memref.buffer,
                    params[0].memref.size);
     return TEE_SUCCESS;
 }
 
 static TEE_Result cipher_buffer(struct aes_cipher *sess,
                                 uint32_t param_types,
                                 TEE_Param params[4])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_MEMREF_OUTPUT,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE);
     if (param_types != exp)
         return TEE_ERROR_BAD_PARAMETERS;
 
     if (params[1].memref.size < params[0].memref.size)
         return TEE_ERROR_BAD_PARAMETERS;
 
     return TEE_CipherUpdate(sess->op_handle,
                             params[0].memref.buffer,
                             params[0].memref.size,
                             params[1].memref.buffer,
                             &params[1].memref.size);
 }
 
 /*----------------------------------------------------------
  * ACIPHER helper implementations
  *---------------------------------------------------------*/
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
         DMSG("Persistent ACIPHER key loaded");
     }
     return res;
 }
 
 static TEE_Result store_persistent_key(TEE_ObjectHandle key)
 {
     TEE_Result res;
     TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
     uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_READ |
                          TEE_DATA_FLAG_ACCESS_WRITE_META |
                          TEE_DATA_FLAG_OVERWRITE;
 
     res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                      ACIPHER_KEY_ID,
                                      ACIPHER_KEY_ID_LEN,
                                      obj_flags,
                                      key,
                                      NULL, 0,
                                      &persistent_key);
     if (res == TEE_SUCCESS)
         TEE_CloseObject(persistent_key);
     return res;
 }
 
 static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
    TEE_Param params[TEE_NUM_PARAMS])
{
const uint32_t exp = TEE_PARAM_TYPES(
TEE_PARAM_TYPE_VALUE_INPUT,
TEE_PARAM_TYPE_NONE,
TEE_PARAM_TYPE_NONE,
TEE_PARAM_TYPE_NONE);
if (pt != exp)
return TEE_ERROR_BAD_PARAMETERS;

uint32_t key_size = params[0].value.a;

/* 如果已有句柄，直接返回 */
if (state->key != TEE_HANDLE_NULL)
return TEE_SUCCESS;

/* 先尝试加载已有的持久密钥 */
if (load_persistent_key(state) == TEE_SUCCESS)
return TEE_SUCCESS;

/* 生成 transient RSA 密钥对 */
TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
TEE_Result res = TEE_AllocateTransientObject(
TEE_TYPE_RSA_KEYPAIR, key_size, &key_obj);
if (res != TEE_SUCCESS)
return res;

res = TEE_GenerateKey(key_obj, key_size, NULL, 0);
if (res != TEE_SUCCESS) {
TEE_FreeTransientObject(key_obj);
return res;
}

/* 存入持久存储 */
res = store_persistent_key(key_obj);
/* 立即释放 transient 对象 */
TEE_FreeTransientObject(key_obj);
if (res != TEE_SUCCESS)
return res;

/* 重新加载持久对象，这样 state->key 是持久句柄 */
return load_persistent_key(state);
}

 
 static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
                           TEE_Param params[TEE_NUM_PARAMS])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_MEMREF_OUTPUT,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE);
     if (pt != exp || state->key == TEE_HANDLE_NULL)
         return TEE_ERROR_BAD_PARAMETERS;
 
     TEE_ObjectInfo key_info;
     TEE_GetObjectInfo1(state->key, &key_info);
     void *inbuf = params[0].memref.buffer;
     uint32_t in_len = params[0].memref.size;
     void *outbuf = params[1].memref.buffer;
     uint32_t out_len = params[1].memref.size;
 
     TEE_OperationHandle op;
     TEE_AllocateOperation(&op, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, key_info.keySize);
     TEE_SetOperationKey(op, state->key);
     TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, in_len, outbuf, &out_len);
     params[1].memref.size = out_len;
     TEE_FreeOperation(op);
     return TEE_SUCCESS;
 }
 
 static TEE_Result cmd_sign(struct acipher *state, uint32_t pt,
                            TEE_Param params[TEE_NUM_PARAMS])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_MEMREF_OUTPUT,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE);
     if (pt != exp || state->key == TEE_HANDLE_NULL)
         return TEE_ERROR_BAD_PARAMETERS;
 
     void *inbuf = params[0].memref.buffer;
     uint32_t in_len = params[0].memref.size;
     uint8_t digest[32];
     uint32_t digest_len = sizeof(digest);
 
     TEE_OperationHandle d_op;
     TEE_AllocateOperation(&d_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
     TEE_DigestDoFinal(d_op, inbuf, in_len, digest, &digest_len);
     TEE_FreeOperation(d_op);
 
     TEE_ObjectInfo key_info;
     TEE_GetObjectInfo1(state->key, &key_info);
 
     void *sig = params[1].memref.buffer;
     uint32_t sig_len = params[1].memref.size;
     TEE_OperationHandle op;
     TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN, key_info.keySize);
     TEE_SetOperationKey(op, state->key);
     TEE_AsymmetricSignDigest(op, NULL, 0, digest, digest_len, sig, &sig_len);
     params[1].memref.size = sig_len;
     TEE_FreeOperation(op);
     return TEE_SUCCESS;
 }
 
 static TEE_Result cmd_verify(struct acipher *state, uint32_t pt,
                              TEE_Param params[TEE_NUM_PARAMS])
 {
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_VALUE_OUTPUT,
         TEE_PARAM_TYPE_NONE);
     if (pt != exp || state->key == TEE_HANDLE_NULL)
         return TEE_ERROR_BAD_PARAMETERS;
 
     void *inbuf = params[0].memref.buffer;
     uint32_t in_len = params[0].memref.size;
     void *sig = params[1].memref.buffer;
     uint32_t sig_len = params[1].memref.size;
 
     uint8_t digest[32];
     uint32_t digest_len = sizeof(digest);
     TEE_OperationHandle d_op;
     TEE_AllocateOperation(&d_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
     TEE_DigestDoFinal(d_op, inbuf, in_len, digest, &digest_len);
     TEE_FreeOperation(d_op);
 
     TEE_ObjectInfo key_info;
     TEE_GetObjectInfo1(state->key, &key_info);
 
     TEE_OperationHandle op;
     TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_VERIFY, key_info.keySize);
     TEE_SetOperationKey(op, state->key);
     TEE_Result res = TEE_AsymmetricVerifyDigest(op, NULL, 0, digest, digest_len, sig, sig_len);
     params[2].value.a = (res == TEE_SUCCESS) ? 1 : 0;
     TEE_FreeOperation(op);
     return TEE_SUCCESS;
 }
 
 static TEE_Result cmd_digest(struct acipher *state, uint32_t pt,
                              TEE_Param params[TEE_NUM_PARAMS])
 {
    (void) state;
     const uint32_t exp = TEE_PARAM_TYPES(
         TEE_PARAM_TYPE_MEMREF_INPUT,
         TEE_PARAM_TYPE_MEMREF_OUTPUT,
         TEE_PARAM_TYPE_NONE,
         TEE_PARAM_TYPE_NONE);
     if (pt != exp)
         return TEE_ERROR_BAD_PARAMETERS;
 
     void *inbuf = params[0].memref.buffer;
     uint32_t in_len = params[0].memref.size;
     void *out = params[1].memref.buffer;
     uint32_t out_len = params[1].memref.size;
 
     TEE_OperationHandle op;
     TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
     TEE_DigestDoFinal(op, inbuf, in_len, out, &out_len);
     params[1].memref.size = out_len;
     TEE_FreeOperation(op);
     return TEE_SUCCESS;
 }
 
 /*----------------------------------------------------------
  * TA Entry Points
  *---------------------------------------------------------*/
 TEE_Result TA_CreateEntryPoint(void)
 {
     return TEE_SUCCESS;
 }
 
 void TA_DestroyEntryPoint(void)
 {
 }
 
 TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                      TEE_Param params[4],
                                      void **session)
 {
     (void)param_types; (void)params;
     struct ta_ctx *ctx = TEE_Malloc(sizeof(*ctx), 0);
     if (!ctx)
         return TEE_ERROR_OUT_OF_MEMORY;
 
     /* Initialize AES context */
     ctx->aes.op_handle = TEE_HANDLE_NULL;
     ctx->aes.key_handle = TEE_HANDLE_NULL;
 
     /* Initialize ACIPHER context */
     ctx->aci.key = TEE_HANDLE_NULL;
     load_persistent_key(&ctx->aci);
 
     *session = ctx;
     return TEE_SUCCESS;
 }
 
 void TA_CloseSessionEntryPoint(void *session)
 {
     struct ta_ctx *ctx = session;
     /* Free AES resources */
     if (ctx->aes.key_handle != TEE_HANDLE_NULL)
         TEE_FreeTransientObject(ctx->aes.key_handle);
     if (ctx->aes.op_handle != TEE_HANDLE_NULL)
         TEE_FreeOperation(ctx->aes.op_handle);
     /* Free ACIPHER key */
     if (ctx->aci.key != TEE_HANDLE_NULL)
     TEE_CloseObject(ctx->aci.key);
     TEE_Free(ctx);
 }
 
 TEE_Result TA_InvokeCommandEntryPoint(void *session,
                                       uint32_t command_id,
                                       uint32_t param_types,
                                       TEE_Param params[4])
 {
     struct ta_ctx *ctx = session;
     TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
     uint32_t err_orig = 0;
 
     switch (command_id) {
     /* Store into Secure Storage */
     case TA_OCRAM_LOAD_CMD_STORE: {
         const uint32_t exp = TEE_PARAM_TYPES(
             TEE_PARAM_TYPE_MEMREF_INPUT,
             TEE_PARAM_TYPE_NONE,
             TEE_PARAM_TYPE_NONE,
             TEE_PARAM_TYPE_NONE);
         if (param_types != exp)
             return TEE_ERROR_BAD_PARAMETERS;
         TEE_ObjectHandle obj;
         res = TEE_CreatePersistentObject(
             TEE_STORAGE_PRIVATE,
             MODEL_DATA_OBJ_ID,
             strlen(MODEL_DATA_OBJ_ID),
             TEE_DATA_FLAG_ACCESS_READ |
             TEE_DATA_FLAG_ACCESS_WRITE |
             TEE_DATA_FLAG_ACCESS_WRITE_META |
             TEE_DATA_FLAG_OVERWRITE,
             TEE_HANDLE_NULL,
             NULL, 0,
             &obj);
         if (res != TEE_SUCCESS)
             return res;
         res = TEE_WriteObjectData(
             obj,
             params[0].memref.buffer,
             params[0].memref.size);
         TEE_CloseObject(obj);
         break;
     }
     /* Load (decrypt then PTA-load) */
     case TA_OCRAM_LOAD_CMD_LOAD: {
         const uint32_t exp = TEE_PARAM_TYPES(
             TEE_PARAM_TYPE_MEMREF_INPUT,
             TEE_PARAM_TYPE_NONE,
             TEE_PARAM_TYPE_NONE,
             TEE_PARAM_TYPE_NONE);
         if (param_types != exp)
             return TEE_ERROR_BAD_PARAMETERS;
         /* Decrypt */
         void *enc_buf   = params[0].memref.buffer;
         uint32_t enc_sz = params[0].memref.size;
         void *plain_buf = TEE_Malloc(enc_sz, 0);
         if (!plain_buf)
             return TEE_ERROR_OUT_OF_MEMORY;
         uint32_t plain_sz = enc_sz;
         res = TEE_CipherUpdate(
             ctx->aes.op_handle,
             enc_buf, enc_sz,
             plain_buf, &plain_sz);
         if (res != TEE_SUCCESS) {
             TEE_Free(plain_buf);
             return res;
         }
         /* PTA load to OCRAM */
         TEE_TASessionHandle s1;
         res = TEE_OpenTASession(
             &pta_ocram_load_uuid, 0,
             TEE_PARAM_TYPES(
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE),
             NULL, &s1, &err_orig);
         if (res != TEE_SUCCESS) {
             TEE_Free(plain_buf);
             return res;
         }
         TEE_Param pt[4] = {0};
         pt[0].memref.buffer = plain_buf;
         pt[0].memref.size   = plain_sz;
         res = TEE_InvokeTACommand(
             s1,
             TEE_TIMEOUT_INFINITE,
             OCRAM_LOAD_CMD,
             TEE_PARAM_TYPES(
                 TEE_PARAM_TYPE_MEMREF_INPUT,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE),
             pt, &err_orig);
         TEE_CloseTASession(s1);
         TEE_Free(plain_buf);
         break;
     }
     /* Read back from OCRAM via PTA */
     case TA_OCRAM_LOAD_CMD_READ: {
         const uint32_t exp = TEE_PARAM_TYPES(
             TEE_PARAM_TYPE_MEMREF_OUTPUT,
             TEE_PARAM_TYPE_NONE,
             TEE_PARAM_TYPE_NONE,
             TEE_PARAM_TYPE_NONE);
         if (param_types != exp)
             return TEE_ERROR_BAD_PARAMETERS;
         TEE_TASessionHandle s2;
         res = TEE_OpenTASession(
             &pta_ocram_read_uuid, 0,
             TEE_PARAM_TYPES(
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE),
             NULL, &s2, &err_orig);
         if (res != TEE_SUCCESS)
             return res;
         TEE_Param pt[4] = {0};
         pt[0].memref.buffer = params[0].memref.buffer;
         pt[0].memref.size   = params[0].memref.size;
         res = TEE_InvokeTACommand(
             s2,
             TEE_TIMEOUT_INFINITE,
             OCRAM_READ_CMD,
             exp, pt, &err_orig);
         if (res == TEE_SUCCESS)
             params[0].memref.size = pt[0].memref.size;
         TEE_CloseTASession(s2);
         break;
     }
     /* AES commands */
     case TA_AES_CMD_PREPARE:
         res = alloc_resources(&ctx->aes, param_types, params);
         break;
     case TA_AES_CMD_SET_KEY:
         res = set_aes_key(&ctx->aes, param_types, params);
         break;
     case TA_AES_CMD_SET_IV:
         res = reset_aes_iv(&ctx->aes, param_types, params);
         break;
     case TA_AES_CMD_CIPHER:
         res = cipher_buffer(&ctx->aes, param_types, params);
         break;
     /* ACIPHER commands */
     case TA_ACIPHER_CMD_GEN_KEY:
         res = cmd_gen_key(&ctx->aci, param_types, params);
         break;
     case TA_ACIPHER_CMD_ENCRYPT:
         res = cmd_enc(&ctx->aci, param_types, params);
         break;
     case TA_ACIPHER_CMD_SIGN:
         res = cmd_sign(&ctx->aci, param_types, params);
         break;
     case TA_ACIPHER_CMD_VERIFY:
         res = cmd_verify(&ctx->aci, param_types, params);
         break;
     case TA_ACIPHER_CMD_DIGEST:
         res = cmd_digest(&ctx->aci, param_types, params);
         break;
     default:
         return TEE_ERROR_NOT_SUPPORTED;
     }
     return res;
 }
 