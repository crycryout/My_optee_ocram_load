#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <secure_storage_ta.h>

#define TEST_OBJECT_SIZE 7000  // 假设文件大小在此范围内，稍后会根据文件大小调整
#define FILENAME "model_data.bin"  // 要存储和读取的文件名

// TEE 资源
struct test_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
    TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
    uint32_t origin;
    TEEC_Result res;

    // 初始化与 TEE 的上下文
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    // 打开与 TA 的会话
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
                                char *data, size_t data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&ctx->sess,
                             TA_SECURE_STORAGE_CMD_WRITE_RAW,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

    return res;
}

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
                               char *data, size_t data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&ctx->sess,
                             TA_SECURE_STORAGE_CMD_READ_RAW,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);

    return res;
}

void store_file_data(struct test_ctx *ctx, const char *filename, const char *obj_id)
{
    char *data = NULL;
    size_t data_len = 0;
    FILE *file = NULL;
    TEEC_Result res;

    // 打开文件
    file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    data_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 为文件数据分配内存
    data = (char *)malloc(data_len);
    if (data == NULL) {
        perror("Failed to allocate memory for file data");
        fclose(file);
        return;
    }

    // 读取文件数据到缓冲区
    fread(data, 1, data_len, file);
    fclose(file);

    printf("Prepare session with the TA\n");
    prepare_tee_session(ctx);

    // 将文件数据写入安全存储
    printf("- Write file data to secure storage\n");
    res = write_secure_object(ctx, obj_id, data, data_len);
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to store file data in secure storage");

    printf("File data has been securely stored.\n");

    // 清理
    free(data);
    terminate_tee_session(ctx);
}

void retrieve_file_data(struct test_ctx *ctx, const char *obj_id, size_t data_len)
{
    char *read_data = (char *)malloc(data_len);  // 分配足够的空间来读取数据
    TEEC_Result res;

    if (read_data == NULL) {
        perror("Failed to allocate memory for reading file data");
        return;
    }

    printf("Prepare session with the TA\n");
    prepare_tee_session(ctx);

    // 读取文件数据
    printf("- Read file data from secure storage\n");
    res = read_secure_object(ctx, obj_id, read_data, data_len);
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to read file data from secure storage");

    // 输出读取的数据
    printf("Read data from secure storage: %.*s\n", (int)data_len, read_data);

    // 清理
    free(read_data);
    terminate_tee_session(ctx);
}

int main(int argc, char *argv[])
{
    struct test_ctx ctx;
    const char *obj_id = "model_data_object";  // 存储的对象ID

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <store|retrieve>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "store") == 0) {
        // 如果传入的是 "store"，则执行存储操作
        store_file_data(&ctx, FILENAME, obj_id);
    } else if (strcmp(argv[1], "retrieve") == 0) {
        // 如果传入的是 "retrieve"，则执行读取操作
        // 这里的 data_len 应该是你存储的文件的大小，假设为 7000 字节
        retrieve_file_data(&ctx, obj_id, TEST_OBJECT_SIZE);
    } else {
        fprintf(stderr, "Invalid argument: %s. Use 'store' or 'retrieve'.\n", argv[1]);
        return 1;
    }

    return 0;
}
