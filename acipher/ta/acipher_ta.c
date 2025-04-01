#include <inttypes.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define AES_KEY_SIZE 16    // AES 密钥长度（字节）
#define AES_BLOCK_SIZE 16  // AES 块大小（字节）

// 硬编码的 AES 密钥（128 位）
static const uint8_t aes_key[AES_KEY_SIZE] = {
    0xd2, 0x83, 0xee, 0x84, 0xb9, 0xe5, 0x68, 0x33,
    0xc4, 0xc5, 0x94, 0x85, 0xba, 0x9a, 0xed, 0xf5
};

// 硬编码的初始化向量（IV）
static const uint8_t aes_iv[AES_BLOCK_SIZE] = {
    0xab, 0x2a, 0x22, 0xe4, 0xc2, 0xf7, 0xa2, 0xe5,
    0xad, 0x4c, 0x03, 0x30, 0x01, 0xdf, 0x39, 0x23
};

// 会话上下文结构体
struct aes_cipher {
    TEE_OperationHandle op_handle;    // 操作句柄
    TEE_ObjectHandle key_handle;      // 密钥句柄
};

// 将十六进制字符串转换为字节数组
static void hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]);
    }
}

// 解密数据的函数
TEE_Result aes_decrypt(struct aes_cipher *sess, const uint8_t *input_data, size_t input_size,
                       uint8_t *output_data, size_t *output_size) {
    TEE_Result res;

    // 创建 AES 操作句柄
    res = TEE_AllocateOperation(&sess->op_handle, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT, AES_KEY_SIZE * 8);
    if (res != TEE_SUCCESS)
        return res;

    // 创建 AES 密钥对象
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_SIZE * 8, &sess->key_handle);
    if (res != TEE_SUCCESS)
        return res;

    // 设置密钥
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, aes_key, AES_KEY_SIZE);
    res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
        return res;

    // 设置操作的密钥
    res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
    if (res != TEE_SUCCESS)
        return res;

    // 初始化操作（设置 IV）
    res = TEE_CipherInit(sess->op_handle, aes_iv, AES_BLOCK_SIZE);
    if (res != TEE_SUCCESS)
        return res;

    // 执行解密操作
    res = TEE_CipherUpdate(sess->op_handle, input_data, input_size, output_data, output_size);
    if (res != TEE_SUCCESS)
        return res;

    return TEE_SUCCESS;
}

// TA 创建入口点
TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

// TA 销毁入口点
void TA_DestroyEntryPoint(void) {
    // 在此处释放资源（如果有）
}

// TA 打开会话入口点
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
                                     TEE_Param __unused params[4], void **session) {
    struct aes_cipher *sess;

    // 分配会话上下文
    sess = TEE_Malloc(sizeof(*sess), 0);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;

    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;

    *session = (void *)sess;
    return TEE_SUCCESS;
}

// TA 关闭会话入口点
void TA_CloseSessionEntryPoint(void *session) {
    struct aes_cipher *sess = (struct aes_cipher *)session;

    // 释放资源
    if (sess->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(sess->key_handle);
    if (sess->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(sess->op_handle);
    TEE_Free(sess);
}

// TA 调用命令入口点
TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
                                      uint32_t param_types, TEE_Param params[4]) {
    struct aes_cipher *sess = (struct aes_cipher *)session;
    TEE_Result res;

    switch (cmd) {
        case TA_AES_CMD_PREPARE:
            // 初始化操作（已在 aes_decrypt 中完成）
            return TEE_SUCCESS;
        case TA_AES_CMD_SET_KEY:
            // 设置密钥（已在 aes_decrypt 中完成）
            return TEE_SUCCESS;
        case TA_AES_CMD_SET_IV:
            // 设置 IV（已在 aes_decrypt 中完成）
            return TEE_SUCCESS;
        case TA_AES_CMD_CIPHER:
            // 执行解密操作
            res = aes_decrypt(sess, params[0].memref.buffer, params[0].memref.size,
                               params[1].memref.buffer, &params[1].memref.size);
            return res;
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}
