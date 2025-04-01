#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <aes_ta.h>

#define AES_TEST_BUFFER_SIZE 4096
#define AES_TEST_KEY_SIZE    16
#define AES_BLOCK_SIZE       16

#define DECODE               0
#define ENCODE               1

/* TEE resources */
struct test_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
    TEEC_UUID uuid = TA_AES_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
             res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

void prepare_aes(struct test_ctx *ctx, int encode)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE);

    op.params[0].value.a = TA_AES_ALGO_CTR;
    op.params[1].value.a = TA_AES_SIZE_128BIT;
    op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
                                    TA_AES_MODE_DECODE;

    res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
             res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = key;
    op.params[0].tmpref.size = key_sz;

    res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
             res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                      TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = iv;
    op.params[0].tmpref.size = iv_sz;

    res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
             res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = in;
    op.params[0].tmpref.size = sz;
    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size = sz;

    res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
             res, origin);
}

void process_file(const char *input_filename, const char *output_filename, int encode)
{
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file)
        errx(1, "Failed to open input file %s", input_filename);

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file)
        errx(1, "Failed to open output file %s", output_filename);

    char key[AES_TEST_KEY_SIZE];
    char iv[AES_BLOCK_SIZE];
    char buffer_in[AES_TEST_BUFFER_SIZE];
    char buffer_out[AES_TEST_BUFFER_SIZE];
    size_t bytes_read;

    memset(key, 0xa5, sizeof(key));  /* Dummy key */
    memset(iv, 0, sizeof(iv));        /* Dummy IV */

    struct test_ctx ctx;
    prepare_tee_session(&ctx);

    prepare_aes(&ctx, encode);
    set_key(&ctx, key, AES_TEST_KEY_SIZE);
    set_iv(&ctx, iv, AES_BLOCK_SIZE);

    while ((bytes_read = fread(buffer_in, 1, sizeof(buffer_in), input_file)) > 0) {
        cipher_buffer(&ctx, buffer_in, buffer_out, bytes_read);
        fwrite(buffer_out, 1, bytes_read, output_file);
    }

    terminate_tee_session(&ctx);

    fclose(input_file);
    fclose(output_file);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <encrypt|decrypt>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        printf("Encrypting input_data.bin to input_data_encrypted.bin\n");
        process_file("input_data.bin", "input_data_encrypted.bin", ENCODE);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        printf("Decrypting input_data_encrypted.bin to input_data_decrypted.bin\n");
        process_file("input_data_encrypted.bin", "input_data_decrypted.bin", DECODE);
    } else {
        printf("Invalid argument. Use 'encrypt' or 'decrypt'.\n");
        return 1;
    }

    return 0;
}
