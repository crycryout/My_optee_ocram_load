/*
 * merged_ta.c
 *
 * Combined TA: OCRAM Load functionality with AES decryption + AES ciphering
 */

 #include <tee_internal_api.h>
 #include <tee_internal_api_extensions.h>
 #include <string.h>
 #include <inttypes.h>
 #include "ocram_load_ta.h"  /* merged header with both OCRAM and AES macros */
 #define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)
 
 /* Constants for OCRAM PTA commands and UUIDs */
 #define MODEL_DATA_OBJ_ID     "model_data.bin"
 /* PTA 命令 ID 与 PTA 实现保持一致 */
 #define OCRAM_LOAD_CMD        0
 #define OCRAM_READ_CMD        0
 /* PTA UUID 与 PTA 实现保持一致 */
 static const TEE_UUID pta_ocram_load_uuid = {
     0xd9e00de1, 0x950b, 0x4eb8,
     { 0xb7, 0xd1, 0x6b, 0x32, 0xde, 0xec, 0x18, 0x57 }
 };
 static const TEE_UUID pta_ocram_read_uuid = {
     0xfa152bfd, 0x7c9e, 0x4c33,
     { 0xb8, 0xac, 0x7f, 0x5c, 0x2b, 0x64, 0x49, 0x92 }
 };
 
 /* AES cipher context per session */
 struct aes_cipher {
     uint32_t algo;
     uint32_t mode;
     uint32_t key_size;
     TEE_OperationHandle op_handle;
     TEE_ObjectHandle key_handle;
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
 
 /* Combined session context */
 struct ta_ctx {
     struct aes_cipher aes;
 };
 
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
 
     /* Load dummy key for reset */
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
     ctx->aes.op_handle = TEE_HANDLE_NULL;
     ctx->aes.key_handle = TEE_HANDLE_NULL;
     *session = ctx;
     return TEE_SUCCESS;
 }
 
 void TA_CloseSessionEntryPoint(void *session)
 {
     struct ta_ctx *ctx = session;
     if (ctx->aes.key_handle != TEE_HANDLE_NULL)
         TEE_FreeTransientObject(ctx->aes.key_handle);
     if (ctx->aes.op_handle != TEE_HANDLE_NULL)
         TEE_FreeOperation(ctx->aes.op_handle);
     TEE_Free(ctx);
 }
 
 /*----------------------------------------------------------
  * Main Command Dispatcher
  *---------------------------------------------------------*/
 
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
         /* 解密 */
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
         /* PTA 加载到 OCRAM */
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
         TEE_Param pt[4] = { 0 };
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
         TEE_Param pt[4] = { 0 };
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
 
     default:
         return TEE_ERROR_NOT_SUPPORTED;
     }
 
     return res;
 }
 