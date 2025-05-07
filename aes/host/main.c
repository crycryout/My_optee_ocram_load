/*
 * merged_client.c
 *
 * Unified OP-TEE client for OCRAM load and AES encryption/decryption
 */

 #include <err.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <fcntl.h>
 #include <unistd.h>
 #include <tee_client_api.h>
 #include "ocram_load_ta.h"  /* Defines both OCRAM and AES UUIDs and commands */
 
 #define FILENAME            "model_data.bin"
 #define READ_SIZE           128  /* must match your PTA’s MAX_READ */
 
 #define AES_TEST_BUFFER_SIZE 4096
 #define AES_TEST_KEY_SIZE    16
 #define AES_BLOCK_SIZE       16
 
 #define DECODE               0
 #define ENCODE               1
 
 /* Helper for AES processing */
 static void prepare_aes(TEEC_Session *sess, int encode) {
     TEEC_Operation op = {0};
     uint32_t origin;
 
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_VALUE_INPUT,
         TEEC_VALUE_INPUT,
         TEEC_VALUE_INPUT,
         TEEC_NONE);
     op.params[0].value.a = TA_AES_ALGO_CTR;
     op.params[1].value.a = TA_AES_SIZE_128BIT;
     op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;
 
     TEEC_Result res = TEEC_InvokeCommand(sess,
                                          TA_AES_CMD_PREPARE,
                                          &op,
                                          &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES PREPARE failed: 0x%x, origin 0x%x", res, origin);
 }
 
 static void set_key(TEEC_Session *sess, char *key, size_t key_sz) {
     TEEC_Operation op = {0};
     uint32_t origin;
 
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_MEMREF_TEMP_INPUT,
         TEEC_NONE, TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = key;
     op.params[0].tmpref.size   = key_sz;
 
     TEEC_Result res = TEEC_InvokeCommand(sess,
                                          TA_AES_CMD_SET_KEY,
                                          &op,
                                          &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES SET_KEY failed: 0x%x, origin 0x%x", res, origin);
 }
 
 static void set_iv(TEEC_Session *sess, char *iv, size_t iv_sz) {
     TEEC_Operation op = {0};
     uint32_t origin;
 
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_MEMREF_TEMP_INPUT,
         TEEC_NONE, TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = iv;
     op.params[0].tmpref.size   = iv_sz;
 
     TEEC_Result res = TEEC_InvokeCommand(sess,
                                          TA_AES_CMD_SET_IV,
                                          &op,
                                          &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES SET_IV failed: 0x%x, origin 0x%x", res, origin);
 }
 
 static void cipher_buffer(TEEC_Session *sess,
                           char *in, char *out, size_t sz) {
     TEEC_Operation op = {0};
     uint32_t origin;
 
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_MEMREF_TEMP_INPUT,
         TEEC_MEMREF_TEMP_OUTPUT,
         TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = in;
     op.params[0].tmpref.size   = sz;
     op.params[1].tmpref.buffer = out;
     op.params[1].tmpref.size   = sz;
 
     TEEC_Result res = TEEC_InvokeCommand(sess,
                                          TA_AES_CMD_CIPHER,
                                          &op,
                                          &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES CIPHER failed: 0x%x, origin 0x%x", res, origin);
 }
 
 static void process_aes_file(const char *infile,
                              const char *outfile,
                              int encode,
                              TEEC_Context *ctx,
                              TEEC_Session *sess) {
     FILE *fin  = fopen(infile,  "rb");
     FILE *fout = fopen(outfile, "wb");
     if (!fin || !fout)
         errx(1, "Failed to open input/output files");
 
     char key[AES_TEST_KEY_SIZE];
     char iv[AES_BLOCK_SIZE];
     char inbuf[AES_TEST_BUFFER_SIZE];
     char outbuf[AES_TEST_BUFFER_SIZE];
     size_t r;
 
     /* Dummy key/IV */
     memset(key, 0xa5, sizeof(key));
     memset(iv, 0,    sizeof(iv));
 
     prepare_aes(sess, encode);
     set_key(sess, key, sizeof(key));
     set_iv(sess, iv,  sizeof(iv));
 
     while ((r = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
         cipher_buffer(sess, inbuf, outbuf, r);
         fwrite(outbuf, 1, r, fout);
     }
 
     fclose(fin);
     fclose(fout);
 }
 
 int main(int argc, char *argv[]) {
     if (argc < 2) {
         fprintf(stderr,
                 "Usage: %s <store|load|read|inference|encrypt|decrypt>\n",
                 argv[0]);
         return 1;
     }
 
     TEEC_Result   res;
     TEEC_Context  ctx;
     TEEC_Session  sess;
     uint32_t      err_origin;
     TEEC_UUID     uuid = TA_OCRAM_LOAD_UUID;
 
     /* Initialize TEE context and session */
     res = TEEC_InitializeContext(NULL, &ctx);
     if (res != TEEC_SUCCESS)
         errx(1, "TEEC_InitializeContext failed: 0x%x", res);
 
     res = TEEC_OpenSession(&ctx,
                            &sess,
                            &uuid,
                            TEEC_LOGIN_PUBLIC,
                            NULL, NULL,
                            &err_origin);
     if (res != TEEC_SUCCESS)
         errx(1, "TEEC_OpenSession failed: 0x%x, origin 0x%x",
              res, err_origin);
 
     if (strcmp(argv[1], "store") == 0) {
         /* STORE */
         FILE *fp = fopen(FILENAME, "rb");
         if (!fp) errx(1, "fopen failed");
         fseek(fp, 0, SEEK_END);
         size_t sz = ftell(fp);
         fseek(fp, 0, SEEK_SET);
 
         void *buf = malloc(sz);
         if (!buf) errx(1, "malloc failed");
         fread(buf, 1, sz, fp);
         fclose(fp);
 
         TEEC_Operation op = {0};
         op.paramTypes = TEEC_PARAM_TYPES(
             TEEC_MEMREF_TEMP_INPUT,
             TEEC_NONE, TEEC_NONE, TEEC_NONE);
         op.params[0].tmpref.buffer = buf;
         op.params[0].tmpref.size   = sz;
 
         res = TEEC_InvokeCommand(&sess,
                                  TA_OCRAM_LOAD_CMD_STORE,
                                  &op,
                                  &err_origin);
         if (res != TEEC_SUCCESS)
             errx(1, "STORE failed: 0x%x, origin 0x%x", res, err_origin);
         free(buf);
         printf("Stored %zu bytes.\n", sz);
 
     } else if (strcmp(argv[1], "load") == 0) {
         /* LOAD */
         res = TEEC_InvokeCommand(&sess,
                                  TA_OCRAM_LOAD_CMD_LOAD,
                                  NULL,
                                  &err_origin);
         if (res != TEEC_SUCCESS)
             errx(1, "LOAD failed: 0x%x, origin 0x%x", res, err_origin);
         printf("Loaded into OCRAM.\n");
 
     } else if (strcmp(argv[1], "read") == 0) {
         /* READ */
         uint8_t buf[READ_SIZE];
         TEEC_Operation op = {0};
         op.paramTypes = TEEC_PARAM_TYPES(
             TEEC_MEMREF_TEMP_OUTPUT,
             TEEC_NONE, TEEC_NONE, TEEC_NONE);
         op.params[0].tmpref.buffer = buf;
         op.params[0].tmpref.size   = READ_SIZE;
 
         res = TEEC_InvokeCommand(&sess,
                                  TA_OCRAM_LOAD_CMD_READ,
                                  &op,
                                  &err_origin);
         if (res != TEEC_SUCCESS)
             errx(1, "READ failed: 0x%x, origin 0x%x", res, err_origin);
 
         for (uint32_t i = 0; i < op.params[0].tmpref.size; i++) {
             if (i % 16 == 0) printf("\n%04x: ", i);
             printf("%02x ", buf[i]);
         }
         printf("\n");
 
     } else if (strcmp(argv[1], "inference") == 0) {
         /* INFERENCE: load -> start M-core -> read */
         /* 1) LOAD */
         res = TEEC_InvokeCommand(&sess,
                                  TA_OCRAM_LOAD_CMD_LOAD,
                                  NULL,
                                  &err_origin);
         if (res != TEEC_SUCCESS)
             errx(1, "INFERENCE LOAD failed: 0x%x, origin 0x%x",
                  res, err_origin);
         /* 2) start M-core */
         int fd = open("/sys/class/remoteproc/remoteproc0/state",
                       O_WRONLY);
         if (fd < 0) errx(1, "open sysfs failed");
         if (write(fd, "start", strlen("start")) < 0)
             errx(1, "write sysfs failed");
         close(fd);
         /* 3) READ */
         uint8_t buf2[READ_SIZE];
         TEEC_Operation op2 = {0};
         op2.paramTypes = TEEC_PARAM_TYPES(
             TEEC_MEMREF_TEMP_OUTPUT,
             TEEC_NONE, TEEC_NONE, TEEC_NONE);
         op2.params[0].tmpref.buffer = buf2;
         op2.params[0].tmpref.size   = READ_SIZE;
 
         res = TEEC_InvokeCommand(&sess,
                                  TA_OCRAM_LOAD_CMD_READ,
                                  &op2,
                                  &err_origin);
         if (res != TEEC_SUCCESS)
             errx(1, "INFERENCE READ failed: 0x%x, origin 0x%x",
                  res, err_origin);
         for (uint32_t i = 0; i < op2.params[0].tmpref.size; i++) {
             if (i % 16 == 0) printf("\n%04x: ", i);
             printf("%02x ", buf2[i]);
         }
         printf("\n");
 
     } else if (strcmp(argv[1], "encrypt") == 0
            || strcmp(argv[1], "decrypt") == 0) {
         int encode = strcmp(argv[1], "encrypt") == 0;
         process_aes_file(
             encode ? "input_data.bin" : "input_data_encrypted.bin",
             encode ? "input_data_encrypted.bin" : "input_data_decrypted.bin",
             encode,
             &ctx,
             &sess);
         printf(
             "%s completed.\n",
             encode ? "Encryption" : "Decryption");
     } else {
         fprintf(stderr, "Unknown command '%s'\n", argv[1]);
     }
 
     TEEC_CloseSession(&sess);
     TEEC_FinalizeContext(&ctx);
     return 0;
 }
 