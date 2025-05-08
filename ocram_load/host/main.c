/*
 * merged_client.c
 *
 * Unified OP-TEE client for OCRAM load, AES encryption/decryption,
 * ACIPHER RSA sign/verify, 'make' command to sign-then-encrypt,
 * and enhanced inference verifying signature before loading plaintext
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

 #include <err.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <fcntl.h>
 #include <unistd.h>
 #include <inttypes.h>
 #include <tee_client_api.h>
 #include "ocram_load_ta.h"
 

#define FILENAME                   "model_data.bin"
#define INPUT_FILE                 "input_data.bin"
#define SIGNATURE_FILE             "signature.bin"
#define OUTPUT_MAKE_FILE           "input_data_signed_encrypted.bin"
#define ENCRYPTED_INPUT_FILE       "input_data_signed_encrypted.bin"
 #define READ_SIZE                  128
 #define AES_TEST_BUFFER_SIZE       4096
 #define AES_TEST_KEY_SIZE          16
 #define AES_BLOCK_SIZE             16
 #define DECODE                     0
 #define ENCODE                     1
 #define DIGEST_SIZE                32
 
 /* Utility to read entire file into buffer */
 static void *read_file(const char *fname, size_t *sz_out) {
     FILE *f = fopen(fname, "rb");
     if (!f) errx(1, "Failed to open %s", fname);
     fseek(f, 0, SEEK_END);
     size_t sz = ftell(f);
     rewind(f);
     void *buf = malloc(sz);
     if (!buf) errx(1, "malloc %zu failed", sz);
     if (fread(buf, 1, sz, f) != sz) errx(1, "fread %s failed", fname);
     fclose(f);
     *sz_out = sz;
     return buf;
 }
 
 /* Utility to write buffer to file */
 static void write_file(const char *fname, const void *buf, size_t sz) {
     FILE *f = fopen(fname, "wb");
     if (!f) errx(1, "Failed to open %s for write", fname);
     if (fwrite(buf, 1, sz, f) != sz) errx(1, "fwrite %s failed", fname);
     fclose(f);
 }
 
 /* AES helpers */
 static void prepare_aes(TEEC_Session *sess, int encode) {
     TEEC_Operation op = {0}; uint32_t origin;
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
         TEEC_VALUE_INPUT, TEEC_NONE);
     op.params[0].value.a = TA_AES_ALGO_CTR;
     op.params[1].value.a = AES_TEST_KEY_SIZE;
     op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;
     TEEC_Result res = TEEC_InvokeCommand(sess, TA_AES_CMD_PREPARE, &op, &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES PREPARE failed: 0x%x origin 0x%x", res, origin);
 }
 static void set_key(TEEC_Session *sess, char *key, size_t key_sz) {
     TEEC_Operation op = {0}; uint32_t origin;
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
         TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = key;
     op.params[0].tmpref.size   = key_sz;
     TEEC_Result res = TEEC_InvokeCommand(sess, TA_AES_CMD_SET_KEY, &op, &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES SET_KEY failed: 0x%x origin 0x%x", res, origin);
 }
 static void set_iv(TEEC_Session *sess, char *iv, size_t iv_sz) {
     TEEC_Operation op = {0}; uint32_t origin;
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
         TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = iv;
     op.params[0].tmpref.size   = iv_sz;
     TEEC_Result res = TEEC_InvokeCommand(sess, TA_AES_CMD_SET_IV, &op, &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES SET_IV failed: 0x%x origin 0x%x", res, origin);
 }
 static void cipher_buffer(TEEC_Session *sess, void *in, void *out, size_t sz) {
     TEEC_Operation op = {0}; uint32_t origin;
     op.paramTypes = TEEC_PARAM_TYPES(
         TEEC_MEMREF_TEMP_INPUT,
         TEEC_MEMREF_TEMP_OUTPUT,
         TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = in;
     op.params[0].tmpref.size   = sz;
     op.params[1].tmpref.buffer = out;
     op.params[1].tmpref.size   = sz;
     TEEC_Result res = TEEC_InvokeCommand(sess, TA_AES_CMD_CIPHER, &op, &origin);
     if (res != TEEC_SUCCESS)
         errx(1, "AES CIPHER failed: 0x%x origin 0x%x", res, origin);
 }
 
 /* Simple AES file processor */
 static void process_aes_file(const char *infile,
                              const char *outfile,
                              int encode,
                              TEEC_Context *ctx,
                              TEEC_Session *sess) {
     FILE *fin  = fopen(infile,  "rb");
     FILE *fout = fopen(outfile, "wb");
     if (!fin || !fout) errx(1, "Failed to open files");
 
     char key[AES_TEST_KEY_SIZE];
     char iv[AES_BLOCK_SIZE];
     char inbuf[AES_TEST_BUFFER_SIZE];
     char outbuf[AES_TEST_BUFFER_SIZE];
     size_t r;
 
     memset(key, 0xa5, sizeof(key));
     memset(iv,  0x00, sizeof(iv));
 
     prepare_aes(sess, encode);
     set_key(sess, key, sizeof(key));
     set_iv(sess, iv, sizeof(iv));
 
     while ((r = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
         cipher_buffer(sess, inbuf, outbuf, r);
         fwrite(outbuf, 1, r, fout);
     }
     fclose(fin);
     fclose(fout);
 }
 
 /* Sign-then-encrypt for 'make' */
 static void make_signed_encrypted(const char *infile,
                                   const char *outfile,
                                   TEEC_Session *sess) {
     size_t data_sz;
     uint8_t *data = read_file(infile, &data_sz);
 
     TEEC_Operation op = {0}; uint32_t eo;
     size_t key_size = 2048;
     op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
     op.params[0].value.a = (uint32_t)key_size;
     if (TEEC_InvokeCommand(sess, TA_ACIPHER_CMD_GEN_KEY, &op, &eo) != TEEC_SUCCESS)
         errx(1, "GEN_KEY failed");
 
     uint8_t digest[DIGEST_SIZE];
     op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
     op.params[0].tmpref.buffer = data;
     op.params[0].tmpref.size   = data_sz;
     op.params[1].tmpref.buffer = digest;
     op.params[1].tmpref.size   = DIGEST_SIZE;
     if (TEEC_InvokeCommand(sess, TA_ACIPHER_CMD_DIGEST, &op, &eo) != TEEC_SUCCESS)
         errx(1, "DIGEST failed");
 
     size_t sig_sz = key_size/8;
     uint8_t *sig = malloc(sig_sz);
     op.params[0].tmpref.buffer = digest;
     op.params[0].tmpref.size   = DIGEST_SIZE;
     op.params[1].tmpref.buffer = sig;
     op.params[1].tmpref.size   = sig_sz;
     if (TEEC_InvokeCommand(sess, TA_ACIPHER_CMD_SIGN, &op, &eo) != TEEC_SUCCESS)
         errx(1, "SIGN failed");
     sig_sz = op.params[1].tmpref.size;
 
     size_t combined_sz = data_sz + sig_sz;
     uint8_t *combined = malloc(combined_sz);
     memcpy(combined, data, data_sz);
     memcpy(combined + data_sz, sig, sig_sz);
     free(data);
     free(sig);
 
     char key[AES_TEST_KEY_SIZE], iv[AES_BLOCK_SIZE];
     memset(key, 0xa5, sizeof(key));
     memset(iv,  0x00, sizeof(iv));
     prepare_aes(sess, ENCODE);
     set_key(sess, key, sizeof(key));
     set_iv(sess, iv, sizeof(iv));
 
     uint8_t *outbuf = malloc(combined_sz);
     cipher_buffer(sess, combined, outbuf, combined_sz);
     write_file(outfile, outbuf, combined_sz);
     free(combined);
     free(outbuf);
     printf("Generated '%s' (%zu bytes)\n", outfile, combined_sz);
 }
 
 int main(int argc, char *argv[]) {
     if (argc < 2) {
         fprintf(stderr, "Usage: %s <store|load|read|encrypt|decrypt|sign|verify|make|inference> [args]\n", argv[0]);
         return 1;
     }
     TEEC_Result res; uint32_t eo;
     TEEC_Context ctx; TEEC_Session sess;
     const TEEC_UUID uuid = TA_OCRAM_LOAD_UUID;
 
     if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS)
         errx(1, "TEEC_InitializeContext failed");
     if (TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo) != TEEC_SUCCESS)
         errx(1, "TEEC_OpenSession failed");
 
     if (strcmp(argv[1], "store") == 0) {
         size_t sz; void *buf = read_file(FILENAME, &sz);
         TEEC_Operation op = {0};
         op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
         op.params[0].tmpref.buffer = buf; op.params[0].tmpref.size = sz;
         if (TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_STORE, &op, &eo) != TEEC_SUCCESS)
             errx(1, "STORE failed");
         printf("Stored %zu bytes.\n", sz);
         free(buf);
 
     } else if (strcmp(argv[1], "load") == 0) {
         TEEC_Operation op = {0};
         op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
         if (TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_LOAD, &op, &eo) != TEEC_SUCCESS)
             errx(1, "LOAD failed");
         printf("Loaded into OCRAM.\n");
 
     } else if (strcmp(argv[1], "read") == 0) {
         uint8_t buf[READ_SIZE];
         TEEC_Operation op = {0};
         op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
         op.params[0].tmpref.buffer = buf; op.params[0].tmpref.size = READ_SIZE;
         if (TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_READ, &op, &eo) != TEEC_SUCCESS)
             errx(1, "READ failed");
         for (uint32_t i=0; i<op.params[0].tmpref.size; i++) {
             if (i%16==0) printf("\n%04x: ", i);
             printf("%02x ", buf[i]);
         }
         printf("\n");
 
     } else if (strcmp(argv[1], "encrypt")==0 || strcmp(argv[1], "decrypt")==0) {
         if (argc!=4) errx(1, "Usage: %s encrypt|decrypt <infile> <outfile>", argv[0]);
         process_aes_file(argv[2], argv[3], strcmp(argv[1],"encrypt")==0, &ctx, &sess);
 
     } else if (strcmp(argv[1], "sign")==0 || strcmp(argv[1], "verify")==0) {
         size_t key_size=2048;
         TEEC_Operation op={0};
         op.paramTypes=TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_NONE,TEEC_NONE,TEEC_NONE);
         op.params[0].value.a=(uint32_t)key_size;
         if (TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &eo)!=TEEC_SUCCESS)
             errx(1, "GEN_KEY failed");
         size_t in_sz; void *inbuf=read_file(INPUT_FILE,&in_sz);
         uint8_t digest[DIGEST_SIZE];
         op.paramTypes=TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE,TEEC_NONE);
         op.params[0].tmpref.buffer=inbuf; op.params[0].tmpref.size=in_sz;
         op.params[1].tmpref.buffer=digest; op.params[1].tmpref.size=DIGEST_SIZE;
         if (TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DIGEST, &op, &eo)!=TEEC_SUCCESS)
             errx(1,"DIGEST failed");
         if (strcmp(argv[1],"sign")==0) {
             size_t sig_sz=key_size/8; void *sig=malloc(sig_sz);
             op.params[0].tmpref.buffer=digest; op.params[0].tmpref.size=DIGEST_SIZE;
             op.params[1].tmpref.buffer=sig; op.params[1].tmpref.size=sig_sz;
             if (TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_SIGN, &op, &eo)!=TEEC_SUCCESS)
                 errx(1,"SIGN failed");
             write_file(SIGNATURE_FILE,sig,op.params[1].tmpref.size);
             printf("Signature saved to %s (%u bytes)\n",SIGNATURE_FILE,(unsigned)op.params[1].tmpref.size);
             free(sig);
         } else {
             size_t sig_sz; void *sig=read_file(SIGNATURE_FILE,&sig_sz);
             op.paramTypes=TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_VALUE_OUTPUT,TEEC_NONE);
             op.params[0].tmpref.buffer=digest; op.params[0].tmpref.size=DIGEST_SIZE;
             op.params[1].tmpref.buffer=sig; op.params[1].tmpref.size=sig_sz;
             if (TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_VERIFY, &op, &eo)!=TEEC_SUCCESS)
                 errx(1,"VERIFY failed");
             printf("Signature is %s\n",op.params[2].value.a?"valid":"invalid");
             free(sig);
         }
         free(inbuf);
 
     } else if (strcmp(argv[1], "make")==0) {
         make_signed_encrypted(INPUT_FILE, OUTPUT_MAKE_FILE, &sess);
 
     } else if (strcmp(argv[1], "inference")==0) 
     {
        /* 1) AES 解密 + 拆分数据与签名 */
        prepare_aes(&sess, DECODE);
        char key[AES_TEST_KEY_SIZE];
        char iv [AES_BLOCK_SIZE];
        memset(key, 0xa5, sizeof(key));
        memset(iv,  0x00, sizeof(iv));
        set_key(&sess, key, sizeof(key));
        set_iv(&sess, iv, sizeof(iv));

        size_t enc_sz;
        uint8_t *enc_buf = read_file(ENCRYPTED_INPUT_FILE, &enc_sz);
        uint8_t *plain_buf = malloc(enc_sz);
        if (!plain_buf) errx(1, "malloc failed");

        cipher_buffer(&sess, enc_buf, plain_buf, enc_sz);
        free(enc_buf);

        size_t key_size = 2048;
        size_t sig_sz   = key_size / 8;
        if (enc_sz < sig_sz) errx(1, "File too small");

        size_t data_sz = enc_sz - sig_sz;
        uint8_t *sig   = plain_buf + data_sz;

        /* 2) 摘要 + 验签 */
        TEEC_Operation op = {0};
        uint32_t eo;
        uint8_t digest[DIGEST_SIZE];

        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = plain_buf;
        op.params[0].tmpref.size   = data_sz;
        op.params[1].tmpref.buffer = digest;
        op.params[1].tmpref.size   = DIGEST_SIZE;
        if (TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DIGEST, &op, &eo) != TEEC_SUCCESS)
            errx(1, "DIGEST failed");

        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_OUTPUT, TEEC_NONE);
        op.params[0].tmpref.buffer = digest;
        op.params[0].tmpref.size   = DIGEST_SIZE;
        op.params[1].tmpref.buffer = sig;
        op.params[1].tmpref.size   = sig_sz;
        if (TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_VERIFY, &op, &eo) != TEEC_SUCCESS)
            errx(1, "VERIFY failed");
        if (!op.params[2].value.a)
            errx(1, "Invalid signature");

        /* 3) Load plaintext 到 OCRAM */
        TEEC_Operation load_op = {0};
        load_op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
            TEEC_NONE, TEEC_NONE);
        load_op.params[0].tmpref.buffer = plain_buf;
        load_op.params[0].tmpref.size   = data_sz;
        if (TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_LOAD, &load_op, &eo) != TEEC_SUCCESS)
            errx(1, "OCRAM LOAD failed");

        printf("Loaded %zu bytes of verified data into OCRAM\n", data_sz);

        /* 4) 通知 remoteproc 启动 */
        {
            const char *rp_path = "/sys/class/remoteproc/remoteproc0/state";
            int fd = open(rp_path, O_WRONLY);
            if (fd < 0)
                errx(1, "open %s failed", rp_path);
            if (write(fd, "start", 5) != 5)
                errx(1, "write to %s failed", rp_path);
            close(fd);
            printf("remoteproc0 state set to 'start'\n");
        }

        /* 5) 通过 PTA 再次读回 OCRAM 内容并打印前 READ_SIZE 字节 */
        {
            uint8_t buf[READ_SIZE] = {0};
            TEEC_Operation read_op = {0};
            read_op.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                TEEC_NONE, TEEC_NONE);
            read_op.params[0].tmpref.buffer = buf;
            read_op.params[0].tmpref.size   = READ_SIZE;
            if (TEEC_InvokeCommand(&sess, TA_OCRAM_LOAD_CMD_READ, &read_op, &eo) != TEEC_SUCCESS)
                errx(1, "OCRAM READ failed");

            printf("First %d bytes read from OCRAM:", READ_SIZE);
            for (uint32_t i = 0; i < read_op.params[0].tmpref.size; i++) {
                if ((i % 16) == 0) printf("\n%04x: ", i);
                printf("%02x ", buf[i]);
            }
            printf("\n");
        }

        free(plain_buf);

    }
      else {
         errx(1,"Unknown command '%s'",argv[1]);
     }
     TEEC_CloseSession(&sess);
     TEEC_FinalizeContext(&ctx);
     return 0;
 }
 