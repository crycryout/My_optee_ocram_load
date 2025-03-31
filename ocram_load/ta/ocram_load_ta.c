/*
 * ocram_load_ta.c
 *
 * 本TA实现了如下功能：
 * 1. TA_OCRAM_LOAD_CMD_INC_VALUE: 占位，示例中直接返回成功。
 * 2. TA_OCRAM_LOAD_CMD_DEC_VALUE: 占位，示例中直接返回成功。
 * 3. TA_OCRAM_LOAD_CMD_MAP_MEMORY: 占位，目前返回不支持。
 * 4. TA_OCRAM_LOAD_CMD_LOAD: 从secure storage中读取 "model_data.bin"
 *    数据，并调用 PTA 将数据加载到指定的物理地址处（例如 0x20480000）。
 * 5. TA_OCRAM_LOAD_CMD_STORE: 从 host 传入数据，将其存储到 secure storage 中，
 *    对象 ID 固定为 MODEL_DATA_OBJ_ID（"model_data.bin"）。
 */

 #include <tee_internal_api.h>
 #include <tee_internal_api_extensions.h>
 #include <string.h>
 #include "ocram_load_ta.h"  /* 包含 TA_OCRAM_LOAD_UUID 及命令 ID 定义 */
 
 #define MODEL_DATA_OBJ_ID     "model_data.bin"
 
 /* PTA 的命令 ID，与 PTA 中实现的保持一致 */
 #define OCRAM_LOAD_CMD        0
 
 /* PTA 的 UUID，与 PTA 实现保持一致 */
 static const TEE_UUID pta_ocram_load_uuid = 
     { 0xd9e00de1, 0x950b, 0x4eb8, { 0xb7, 0xd1, 0x6b, 0x32, 0xde, 0xec, 0x18, 0x57 } };
 
 /* TA入口点：初始化 */
 TEE_Result TA_CreateEntryPoint(void)
 {
     return TEE_SUCCESS;
 }
 
 void TA_DestroyEntryPoint(void)
 {
     /* Nothing to do */
 }
 
 /* TA会话打开入口点 */
 TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                     TEE_Param params[4],
                                     void **session)
 {
     (void)param_types;
     (void)params;
     (void)session;
     return TEE_SUCCESS;
 }
 
 /* TA会话关闭入口点 */
 void TA_CloseSessionEntryPoint(void *session)
 {
     (void)session;
 }
 
 /* TA命令分发入口 */
 TEE_Result TA_InvokeCommandEntryPoint(void *session,
                                       uint32_t command_id,
                                       uint32_t param_types,
                                       TEE_Param params[4])
 {
     TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
     uint32_t ret_orig = 0;
 
     (void)session;
 
     switch (command_id) {
     case TA_OCRAM_LOAD_CMD_INC_VALUE:
         /* 占位示例 */
         DMSG("TA_OCRAM_LOAD_CMD_INC_VALUE 命令被调用");
         res = TEE_SUCCESS;
         break;
 
     case TA_OCRAM_LOAD_CMD_DEC_VALUE:
         /* 占位示例 */
         DMSG("TA_OCRAM_LOAD_CMD_DEC_VALUE 命令被调用");
         res = TEE_SUCCESS;
         break;
 
     case TA_OCRAM_LOAD_CMD_MAP_MEMORY:
         /* 占位示例：内存映射功能，此处未实现 */
         DMSG("TA_OCRAM_LOAD_CMD_MAP_MEMORY 命令未实现");
         res = TEE_ERROR_NOT_IMPLEMENTED;
         break;
 
     case TA_OCRAM_LOAD_CMD_STORE:
     {
         /* 存储功能：
          * 从 host 传入数据（期望参数：param[0] 为 MEMREF_INPUT），
          * 将其存储到 secure storage 中，使用固定对象 ID MODEL_DATA_OBJ_ID。
          */
         const uint32_t exp_param_types =
             TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                             TEE_PARAM_TYPE_NONE,
                             TEE_PARAM_TYPE_NONE,
                             TEE_PARAM_TYPE_NONE);
         if (param_types != exp_param_types) {
             EMSG("TA_OCRAM_LOAD_CMD_STORE: 参数类型错误");
             return TEE_ERROR_BAD_PARAMETERS;
         }
         void *data = params[0].memref.buffer;
         size_t data_size = params[0].memref.size;
 
         TEE_ObjectHandle object;
         uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
                          TEE_DATA_FLAG_ACCESS_WRITE |
                          TEE_DATA_FLAG_ACCESS_WRITE_META |
                          TEE_DATA_FLAG_OVERWRITE;
         res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                          MODEL_DATA_OBJ_ID,
                                          strlen(MODEL_DATA_OBJ_ID),
                                          flags,
                                          TEE_HANDLE_NULL,
                                          NULL, 0,
                                          &object);
         if (res != TEE_SUCCESS) {
             EMSG("TA_OCRAM_LOAD_CMD_STORE: TEE_CreatePersistentObject 失败, res=0x%x", res);
             return res;
         }
         res = TEE_WriteObjectData(object, data, data_size);
         if (res != TEE_SUCCESS) {
             EMSG("TA_OCRAM_LOAD_CMD_STORE: TEE_WriteObjectData 失败, res=0x%x", res);
             TEE_CloseAndDeletePersistentObject1(object);
             return res;
         }
         TEE_CloseObject(object);
         DMSG("TA_OCRAM_LOAD_CMD_STORE: 成功存储数据, 大小 = %zu 字节", data_size);
         break;
     }
 
     case TA_OCRAM_LOAD_CMD_LOAD:
     {
         /* 加载功能：
          * 从 secure storage 中读取 MODEL_DATA_OBJ_ID 对应的数据，
          * 并调用 PTA 将数据加载到指定的物理地址（例如 0x20480000）。
          */
         TEE_ObjectHandle object;
         TEE_ObjectInfo object_info;
         uint32_t read_bytes;
 
         res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                        MODEL_DATA_OBJ_ID,
                                        strlen(MODEL_DATA_OBJ_ID),
                                        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
                                        &object);
         if (res != TEE_SUCCESS) {
             EMSG("TA_OCRAM_LOAD_CMD_LOAD: 打开持久对象失败, res=0x%x", res);
             return res;
         }
 
         res = TEE_GetObjectInfo1(object, &object_info);
         if (res != TEE_SUCCESS) {
             EMSG("TA_OCRAM_LOAD_CMD_LOAD: 获取对象信息失败, res=0x%x", res);
             TEE_CloseObject(object);
             return res;
         }
 
         void *data_buffer = TEE_Malloc(object_info.dataSize, 0);
         if (!data_buffer) {
             TEE_CloseObject(object);
             return TEE_ERROR_OUT_OF_MEMORY;
         }
 
         res = TEE_ReadObjectData(object, data_buffer, object_info.dataSize, &read_bytes);
         if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
             EMSG("TA_OCRAM_LOAD_CMD_LOAD: 读取对象数据失败, res=0x%x", res);
             TEE_Free(data_buffer);
             TEE_CloseObject(object);
             return TEE_ERROR_GENERIC;
         }
         TEE_CloseObject(object);
 
         /* 打开与 OCRAM load PTA 的会话 */
         TEE_TASessionHandle pta_session;
         res = TEE_OpenTASession(&pta_ocram_load_uuid,
                                 0,
                                 TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                                 TEE_PARAM_TYPE_NONE,
                                                 TEE_PARAM_TYPE_NONE,
                                                 TEE_PARAM_TYPE_NONE),
                                 NULL,
                                 &pta_session,
                                 &ret_orig);
         if (res != TEE_SUCCESS) {
             EMSG("TA_OCRAM_LOAD_CMD_LOAD: 打开 PTA 会话失败, res=0x%x", res);
             TEE_Free(data_buffer);
             return res;
         }
 
         /* 通过 PTA 调用加载操作 */
         TEE_Param pta_params[4] = {0};
         pta_params[0].memref.buffer = data_buffer;
         pta_params[0].memref.size   = object_info.dataSize;
 
         res = TEE_InvokeTACommand(pta_session,
                                   TEE_TIMEOUT_INFINITE,
                                   OCRAM_LOAD_CMD,
                                   TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                                   TEE_PARAM_TYPE_NONE,
                                                   TEE_PARAM_TYPE_NONE,
                                                   TEE_PARAM_TYPE_NONE),
                                   pta_params,
                                   &ret_orig);
 
         TEE_CloseTASession(pta_session);
         TEE_Free(data_buffer);
         break;
     }
 
     default:
         EMSG("不支持的命令ID: %u", command_id);
         res = TEE_ERROR_BAD_PARAMETERS;
         break;
     }
 
     return res;
 }
 