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
 
 #define FILENAME             "model_data.bin"
 #define READ_SIZE            128   /* must match your PTA’s MAX_READ */
 
 #define AES_TEST_BUFFER_SIZE 4096
 #define AES_TEST_KEY_SIZE    16
 #define AES_BLOCK_SIZE       16
 
 /* Helper commands */
 #define DECODE               0
 #define ENCODE               1
 #define AES128_KEY_BIT_SIZE		128
 #define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
 #define AES256_KEY_BIT_SIZE		256
 #define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)
 
 /* AES helper: prepare algorithm/mode/keysize */
 static void prepare_aes(TEEC_Session *sess, int encode) {
     TEEC_Operation op = { 0 };
     uint32_t origin;
 
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_VALUE_INPUT,    /* algo */
         TEEC_VALUE_INPUT,    /* key size */
         TEEC_VALUE_INPUT,    /* encrypt/decrypt */
         TEEC_NONE);
     op.params[0].value.a = TA_AES_ALGO_CTR;
     op.params[1].value.a = AES128_KEY_BYTE_SIZE;
     op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;
 
     TEEC_Result res = TEEC_InvokeCommand(sess,
                                          TA_AES_CMD_PREPARE,
                                          &op,
                                          &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES PREPARE failed: 0x%x origin 0x%x", res, origin);
 }
 
 /* AES helper: set key bytes */
 static void set_key(TEEC_Session *sess, char *key, size_t key_sz) {
     TEEC_Operation op = { 0 };
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
         errx(1, "AES SET_KEY failed: 0x%x origin 0x%x", res, origin);
 }
 
 /* AES helper: set IV bytes */
 static void set_iv(TEEC_Session *sess, char *iv, size_t iv_sz) {
     TEEC_Operation op = { 0 };
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
         errx(1, "AES SET_IV failed: 0x%x origin 0x%x", res, origin);
 }
 
 /* AES helper: encrypt/decrypt buffer */
 static void cipher_buffer(TEEC_Session *sess,
                           char *in, char *out, size_t sz) {
     TEEC_Operation op = { 0 };
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
         errx(1, "AES CIPHER failed: 0x%x origin 0x%x", res, origin);
 }
 
 /* Process a file: read plaintext or ciphertext, run AES, write output */
 static void process_aes_file(const char *infile,
                              const char *outfile,
                              int encode,
                              TEEC_Context *ctx,
                              TEEC_Session *sess) {
     FILE *fin  = fopen(infile,  "rb");
     FILE *fout = fopen(outfile, "wb");
     if (!fin || !fout)
         errx(1, "Failed to open input/output file");
 
     char key[AES_TEST_KEY_SIZE];
     char iv[AES_BLOCK_SIZE];
     char inbuf[AES_TEST_BUFFER_SIZE];
     char outbuf[AES_TEST_BUFFER_SIZE];
     size_t r;
 
     /* Dummy key/IV—you可以换成真实 key/iv */
     memset(key, 0xa5, sizeof(key));
     memset(iv, 0x00, sizeof(iv));
 
     /* 配置 AES */
     prepare_aes(sess, encode);
     set_key(sess, key, sizeof(key));
     set_iv(sess, iv, sizeof(iv));
 
     /* 分段加解密 */
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
 
     TEEC_Result  res;
     TEEC_Context ctx;
     TEEC_Session sess;
     uint32_t     err_origin;
     TEEC_UUID    uuid = TA_OCRAM_LOAD_UUID;
 
     /* 初始化 TEE context 与 session */
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
         errx(1, "TEEC_OpenSession failed: 0x%x origin 0x%x",
              res, err_origin);
 
     if (strcmp(argv[1], "store") == 0) {
         /* STORE -> Persistent Storage */
         FILE *fp = fopen(FILENAME, "rb");
         if (!fp) errx(1, "fopen failed");
         fseek(fp, 0, SEEK_END);
         size_t sz = ftell(fp);
         fseek(fp, 0, SEEK_SET);
 
         void *buf = malloc(sz);
         if (!buf) errx(1, "malloc failed");
         fread(buf, 1, sz, fp);
         fclose(fp);
 
         TEEC_Operation op = { 0 };
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
             errx(1, "STORE failed: 0x%x origin 0x%x", res, err_origin);
         free(buf);
         printf("Stored %zu bytes.\n", sz);
 
     } else if (strcmp(argv[1], "load") == 0) {
         /* LOAD -> 解密并加载到 OCRAM */
         TEEC_Operation op = {0};
         op.paramTypes = TEEC_PARAM_TYPES(
             TEEC_MEMREF_TEMP_INPUT,
             TEEC_NONE, TEEC_NONE, TEEC_NONE);
         /* 你可以把 buf/size 放在 op.params[0] 中，
            或者把 NULL 传给 TA（依你 TA 实现而定） */
         /* 这里假设 TA 内部已准备好加密上下文，并直接 LOAD */
         res = TEEC_InvokeCommand(&sess,
                                  TA_OCRAM_LOAD_CMD_LOAD,
                                  &op,
                                  &err_origin);
         if (res != TEEC_SUCCESS)
             errx(1, "LOAD failed: 0x%x origin 0x%x", res, err_origin);
         printf("Loaded into OCRAM.\n");
 
     } else if (strcmp(argv[1], "read") == 0) {
         /* READ -> 从 OCRAM 读回 */
         uint8_t buf[READ_SIZE];
         TEEC_Operation op = { 0 };
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
             errx(1, "READ failed: 0x%x origin 0x%x", res, err_origin);
 
         for (uint32_t i = 0; i < op.params[0].tmpref.size; i++) {
             if (i % 16 == 0) printf("\n%04x: ", i);
             printf("%02x ", buf[i]);
         }
         printf("\n");
 
     } else if (strcmp(argv[1], "inference") == 0) 
     {
        /* INFERENCE:
         *   0) 配置 AES 解密
         *   1) 读取加密数据并 LOAD 到 OCRAM
         *   2) 启动 M 核固件
         *   3) READ 并打印结果
         */
    
        /* 0) 在 TA 内部先配置好 AES-CTR 解密 */
        prepare_aes(&sess, DECODE);
        {
            /* Dummy key/IV，要跟加密时用的保持一致 */
            char key[AES_TEST_KEY_SIZE];
            char iv[AES_BLOCK_SIZE];
            memset(key, 0xa5, sizeof(key));
            memset(iv, 0x00, sizeof(iv));
            set_key(&sess, key, sizeof(key));
            set_iv(&sess, iv, sizeof(iv));
        }
    
        /* 1) 从文件加载加密后的 input_data_encrypted.bin */
        FILE *f = fopen("input_data_encrypted.bin", "rb");
        if (!f) errx(1, "fopen encrypted file failed");
        fseek(f, 0, SEEK_END);
        size_t sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        void *enc_buf = malloc(sz);
        if (!enc_buf) errx(1, "malloc failed");
        if (fread(enc_buf, 1, sz, f) != sz) errx(1, "fread failed");
        fclose(f);
    
        /* 构造 TEEC_Operation，把加密数据作为 MEMREF_INPUT 传给 TA */
        TEEC_Operation op = { 0 };
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = enc_buf;
        op.params[0].tmpref.size   = sz;
    
        /* 调用 TA 来解密并加载到 OCRAM */
        res = TEEC_InvokeCommand(&sess,
                                 TA_OCRAM_LOAD_CMD_LOAD,
                                 &op,
                                 &err_origin);
        free(enc_buf);
        if (res != TEEC_SUCCESS)
            errx(1, "INFERENCE LOAD failed: 0x%x origin 0x%x",
                 res, err_origin);
    
        /* 2) 启动 M 核固件（remoteproc）*/
        int fd = open("/sys/class/remoteproc/remoteproc0/state", O_WRONLY);
        if (fd < 0) errx(1, "open sysfs failed");
        if (write(fd, "start", strlen("start")) < 0)
            errx(1, "write sysfs failed");
        close(fd);
    
        /* 3) 从 OCRAM 读回结果并打印 */
        uint8_t buf2[READ_SIZE];
        TEEC_Operation op2 = { 0 };
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
            errx(1, "INFERENCE READ failed: 0x%x origin 0x%x",
                 res, err_origin);
    
        printf("Read %u bytes from OCRAM:\n", (unsigned)op2.params[0].tmpref.size);
        for (uint32_t i = 0; i < op2.params[0].tmpref.size; i++) {
            if (i % 16 == 0) printf("\n%04x: ", i);
            printf("%02x ", buf2[i]);
        }
        printf("\n");
    }
      else {
         fprintf(stderr, "Unknown command '%s'\n", argv[1]);
     }
 
     TEEC_CloseSession(&sess);
     TEEC_FinalizeContext(&ctx);
     return 0;
 }
 