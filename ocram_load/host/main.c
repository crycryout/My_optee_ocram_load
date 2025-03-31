#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "ocram_load_ta.h"

#define FILENAME "model_data.bin"

int main(int argc, char *argv[])
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_OCRAM_LOAD_UUID;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <store|load>\n", argv[0]);
        return 1;
    }

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession failed with code 0x%x, origin 0x%x", res, err_origin);

    if (strcmp(argv[1], "store") == 0) {
        /* 读取本地文件数据 */
        FILE *fp = fopen(FILENAME, "rb");
        if (!fp) {
            perror("fopen");
            goto cleanup;
        }
        fseek(fp, 0, SEEK_END);
        size_t filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char *buffer = malloc(filesize);
        if (!buffer) {
            fclose(fp);
            fprintf(stderr, "Failed to allocate memory\n");
            goto cleanup;
        }
        if (fread(buffer, 1, filesize, fp) != filesize) {
            perror("fread");
            free(buffer);
            fclose(fp);
            goto cleanup;
        }
        fclose(fp);

        /* 设置 TA 参数：单个 MEMREF 输入参数 */
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].tmpref.buffer = buffer;
        op.params[0].tmpref.size = filesize;

        printf("Storing file data into secure storage...\n");
        res = TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_STORE, &op, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InvokeCommand (store) failed with code 0x%x, origin 0x%x", res, err_origin);
        printf("File stored successfully.\n");
        free(buffer);
    } else if (strcmp(argv[1], "load") == 0) {
        /* load 操作无需传入参数 */
        printf("Loading file data from secure storage and loading into OCRAM...\n");
        res = TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_LOAD, NULL, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InvokeCommand (load) failed with code 0x%x, origin 0x%x", res, err_origin);
        printf("File loaded successfully into OCRAM.\n");
    } else {
        fprintf(stderr, "Invalid command. Use 'store' or 'load'.\n");
        goto cleanup;
    }

cleanup:
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return res;
}
