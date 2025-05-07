#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "ocram_load_ta.h"

#define FILENAME    "model_data.bin"
#define READ_SIZE   128    /* must match your PTA’s MAX_READ */

int main(int argc, char *argv[])
{
    TEEC_Result    res;
    TEEC_Context   ctx;
    TEEC_Session   sess;
    TEEC_Operation op;
    uint32_t       err_origin;
    TEEC_UUID      uuid = TA_OCRAM_LOAD_UUID;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <store|load|read>\n", argv[0]);
        return 1;
    }

    /* Initialize context & open session */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed: 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession failed: 0x%x, origin 0x%x",
             res, err_origin);

    if (strcmp(argv[1], "store") == 0) {
        /* ========== STORE ========== */
        FILE *fp = fopen(FILENAME, "rb");
        if (!fp) { perror("fopen"); goto cleanup; }
        fseek(fp, 0, SEEK_END);
        size_t filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        void *buffer = malloc(filesize);
        if (!buffer) {
            fclose(fp);
            errx(1, "malloc failed");
        }
        if (fread(buffer, 1, filesize, fp) != filesize) {
            perror("fread");
            free(buffer);
            fclose(fp);
            goto cleanup;
        }
        fclose(fp);

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = buffer;
        op.params[0].tmpref.size   = filesize;

        printf("Storing file into secure storage…\n");
        res = TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_STORE, &op, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "STORE failed: 0x%x, origin 0x%x", res, err_origin);
        printf("Stored %zu bytes.\n", filesize);
        free(buffer);

    } else if (strcmp(argv[1], "load") == 0) {
        /* ========== LOAD ========== */
        printf("Loading into OCRAM…\n");
        res = TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_LOAD, NULL, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "LOAD failed: 0x%x, origin 0x%x", res, err_origin);
        printf("Loaded into OCRAM.\n");

    } else if (strcmp(argv[1], "read") == 0) {
        /* ========== READ ========== */
        uint8_t buffer[READ_SIZE];
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = buffer;
        op.params[0].tmpref.size   = READ_SIZE;

        printf("Reading back from OCRAM…\n");
        res = TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_READ, &op, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "READ failed: 0x%x, origin 0x%x", res, err_origin);

        /* op.params[0].tmpref.size now contains actual bytes read */
        printf("Read %u bytes:\n", (unsigned)op.params[0].tmpref.size);
        for (uint32_t i = 0; i < op.params[0].tmpref.size; i++) {
            if (i % 16 == 0) printf("\n%04x: ", i);
            printf("%02x ", buffer[i]);
        }
        printf("\n");

    } else {
        fprintf(stderr, "Invalid command '%s'. Use 'store', 'load', or 'read'.\n", argv[1]);
    }

cleanup:
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return res == TEEC_SUCCESS ? 0 : 1;
}
