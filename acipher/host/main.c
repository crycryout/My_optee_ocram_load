// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

 #include <err.h>
 #include <inttypes.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 /* OP-TEE TEE client API */
 #include <tee_client_api.h>
 
 /* For the UUID (found in the TA's h-file(s)) */
 #include <acipher_ta.h>
 
 static void usage(void)
 {
	 fprintf(stderr, "usage: decrypt_payload\n");
	 exit(1);
 }
 
 static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
 {
	 errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
 }
 
 int main(void)
 {
	 TEEC_Result res;
	 uint32_t eo;
	 TEEC_Context ctx;
	 TEEC_Session sess;
	 TEEC_Operation op;
	 FILE *file;
	 size_t enc_size;
	 void *enc_buf;
	 size_t n;
	 const TEEC_UUID uuid = TA_ACIPHER_UUID;
 
	 /* 打开加密文件 */
	 file = fopen("payload.bin.enc", "rb");
	 if (!file)
		 err(1, "Cannot open payload.bin.enc");
 
	 /* 获取文件大小 */
	 fseek(file, 0, SEEK_END);
	 enc_size = ftell(file);
	 fseek(file, 0, SEEK_SET);
 
	 /* 分配缓冲区并读取文件内容 */
	 enc_buf = malloc(enc_size);
	 if (!enc_buf)
		 err(1, "Cannot allocate buffer for encrypted data");
	 fread(enc_buf, 1, enc_size, file);
	 fclose(file);
 
	 /* 初始化 TEEC 上下文 */
	 res = TEEC_InitializeContext(NULL, &ctx);
	 if (res)
		 errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);
 
	 /* 打开与 TA 的会话 */
	 res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
	 if (res)
		 teec_err(res, eo, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC)");
 
	 /* 设置操作参数 */
	 memset(&op, 0, sizeof(op));
	 op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	 op.params[0].tmpref.buffer = enc_buf;
	 op.params[0].tmpref.size = enc_size;
	 op.params[1].tmpref.buffer = malloc(enc_size); /* 分配足够大的缓冲区来存放解密后的数据 */
	 if (!op.params[1].tmpref.buffer)
		 err(1, "Cannot allocate buffer for decrypted data");
 
	 /* 调用 TA 的解密命令 */
	 res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DECRYPT, &op, &eo);
	 if (res)
		 teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_DECRYPT)");
 
	 /* 将解密后的数据写入文件 */
	 file = fopen("payload_decrypted.bin", "wb");
	 if (!file)
		 err(1, "Cannot open payload_decrypted.bin for writing");
	 fwrite(op.params[1].tmpref.buffer, 1, enc_size, file);
	 fclose(file);
 
	 /* 清理 */
	 free(enc_buf);
	 free(op.params[1].tmpref.buffer);
	 TEEC_CloseSession(&sess);
	 TEEC_FinalizeContext(&ctx);
 
	 printf("Decryption complete. Output written to payload_decrypted.bin\n");
	 return 0;
 }
 