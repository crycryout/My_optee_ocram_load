// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

 #include <err.h>
 #include <inttypes.h>
 #include <limits.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 /* OP-TEE TEE client API (built by optee_client) */
 #include <tee_client_api.h>
 /* For the UUID (found in the TA's h-file(s)) */
 #include <acipher_ta.h>
 
 #define DIGEST_SIZE 32  /* SHA-256 输出固定 32 字节 */
 
 /* 打印用法信息 */
 static void usage(int argc, char *argv[])
 {
	 const char *pname = argc ? argv[0] : "acipher";
	 fprintf(stderr, "Usage: %s <key_size> <sign|verify>\n", pname);
	 exit(1);
 }
 
 /* 解析命令行参数：第一个参数为密钥大小，第二个参数为操作（sign 或 verify） */
 static void get_args(int argc, char *argv[], size_t *key_size, char **cmd)
 {
	 char *ep;
	 long ks;
 
	 if (argc != 3) {
		 warnx("Unexpected number of arguments %d (expected 2)", argc - 1);
		 usage(argc, argv);
	 }
 
	 ks = strtol(argv[1], &ep, 0);
	 if (*ep) {
		 warnx("Cannot parse key_size \"%s\"", argv[1]);
		 usage(argc, argv);
	 }
	 if (ks <= 0 || ks == LONG_MAX) {
		 warnx("Bad key_size \"%s\" (%ld)", argv[1], ks);
		 usage(argc, argv);
	 }
	 *key_size = (size_t)ks;
	 *cmd = argv[2];
 }
 
 /* 读取文件内容，返回内存缓冲区和文件大小 */
 static void *read_file(const char *filename, size_t *size_out)
 {
	 FILE *f;
	 void *buffer;
	 size_t size;
 
	 f = fopen(filename, "rb");
	 if (!f)
		 errx(1, "Failed to open file: %s", filename);
 
	 fseek(f, 0, SEEK_END);
	 size = ftell(f);
	 rewind(f);
 
	 buffer = malloc(size);
	 if (!buffer)
		 errx(1, "Failed to allocate memory for file: %s", filename);
 
	 if (fread(buffer, 1, size, f) != size) {
		 fclose(f);
		 errx(1, "Failed to read file: %s", filename);
	 }
	 fclose(f);
	 *size_out = size;
	 return buffer;
 }
 
 /* 将数据写入文件 */
 static void write_file(const char *filename, const void *buffer, size_t size)
 {
	 FILE *f = fopen(filename, "wb");
	 if (!f)
		 errx(1, "Failed to open file for writing: %s", filename);
	 if (fwrite(buffer, 1, size, f) != size) {
		 fclose(f);
		 errx(1, "Failed to write file: %s", filename);
	 }
	 fclose(f);
 }
 
 /* 打印 TEEC 调用错误信息 */
 static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
 {
	 errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
 }
 
 int main(int argc, char *argv[])
 {
	 TEEC_Result res;
	 uint32_t eo;
	 TEEC_Context ctx;
	 TEEC_Session sess;
	 TEEC_Operation op;
	 size_t key_size;
	 char *command;
	 void *input_data;
	 size_t input_data_len;
	 void *signature = NULL;
	 size_t signature_size;
	 void *digest = NULL;
	 size_t digest_size = DIGEST_SIZE;
	 const TEEC_UUID uuid = TA_ACIPHER_UUID;
 
	 /* 解析命令行参数 */
	 get_args(argc, argv, &key_size, &command);
 
	 /* 读取 input_data.bin 文件 */
	 input_data = read_file("input_data.bin", &input_data_len);
 
	 /* 分配用于存放摘要的缓冲区 */
	 digest = malloc(DIGEST_SIZE);
	 if (!digest)
		 errx(1, "Failed to allocate memory for digest");
 
	 /* 初始化 TEE 上下文 */
	 res = TEEC_InitializeContext(NULL, &ctx);
	 if (res)
		 errx(1, "TEEC_InitializeContext failed: %#" PRIx32, res);
 
	 /* 打开 TA 会话 */
	 res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
	 if (res)
		 teec_err(res, eo, "TEEC_OpenSession");
 
	 /* 生成 RSA 密钥对 */
	 memset(&op, 0, sizeof(op));
	 op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					  TEEC_NONE, TEEC_NONE);
	 op.params[0].value.a = key_size;
	 res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &eo);
	 if (res)
		 teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_GEN_KEY)");
 
	 if (strcmp(command, "sign") == 0) {
		 /* 签名流程：
		  * 1. 生成摘要：调用 TA_ACIPHER_CMD_DIGEST，
		  *    in: input_data.bin 内容；out: 摘要（32字节）
		  * 2. 使用 TA_ACIPHER_CMD_SIGN 对摘要进行签名
		  */
		 memset(&op, 0, sizeof(op));
		 op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_NONE, TEEC_NONE);
		 op.params[0].tmpref.buffer = input_data;
		 op.params[0].tmpref.size = input_data_len;
		 op.params[1].tmpref.buffer = digest;
		 op.params[1].tmpref.size = DIGEST_SIZE;
		 res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DIGEST, &op, &eo);
		 if (res)
			 teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_DIGEST)");
 
		 /* 分配签名缓冲区，大小为密钥大小/8 */
		 signature_size = key_size / 8;
		 signature = malloc(signature_size);
		 if (!signature)
			 errx(1, "Failed to allocate memory for signature");
 
		 memset(&op, 0, sizeof(op));
		 op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_NONE, TEEC_NONE);
		 /* 将生成的摘要作为签名输入 */
		 op.params[0].tmpref.buffer = digest;
		 op.params[0].tmpref.size = DIGEST_SIZE;
		 op.params[1].tmpref.buffer = signature;
		 op.params[1].tmpref.size = signature_size;
		 res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_SIGN, &op, &eo);
		 if (res)
			 teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_SIGN)");
 
		 /* 将签名写入 signature.bin 文件 */
		 write_file("signature.bin", signature, op.params[1].tmpref.size);
		 printf("Signature created and saved to signature.bin (size: %zu bytes).\n",
				op.params[1].tmpref.size);
	 } else if (strcmp(command, "verify") == 0) {
		 /* 验证流程：
		  * 1. 生成摘要：调用 TA_ACIPHER_CMD_DIGEST，
		  *    in: input_data.bin 内容；out: 摘要（32字节）
		  * 2. 读取 signature.bin 中的签名
		  * 3. 调用 TA_ACIPHER_CMD_VERIFY 对摘要和签名进行验证
		  */
		 memset(&op, 0, sizeof(op));
		 op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_NONE, TEEC_NONE);
		 op.params[0].tmpref.buffer = input_data;
		 op.params[0].tmpref.size = input_data_len;
		 op.params[1].tmpref.buffer = digest;
		 op.params[1].tmpref.size = DIGEST_SIZE;
		 res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DIGEST, &op, &eo);
		 if (res)
			 teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_DIGEST)");
 
		 /* 读取 signature.bin 文件 */
		 signature = read_file("signature.bin", &signature_size);
 
		 memset(&op, 0, sizeof(op));
		 op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_INPUT,
						  TEEC_VALUE_OUTPUT,
						  TEEC_NONE);
		 /* 使用生成的摘要和读取到的签名进行验证 */
		 op.params[0].tmpref.buffer = digest;
		 op.params[0].tmpref.size = DIGEST_SIZE;
		 op.params[1].tmpref.buffer = signature;
		 op.params[1].tmpref.size = signature_size;
 
		 res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_VERIFY, &op, &eo);
		 if (res)
			 teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_VERIFY)");
 
		 if (op.params[2].value.a == 1)
			 printf("Signature verification succeeded: signature is valid.\n");
		 else
			 printf("Signature verification failed: signature is invalid.\n");
	 } else {
		 warnx("Unknown command: %s", command);
		 usage(argc, argv);
	 }
 
	 TEEC_CloseSession(&sess);
	 TEEC_FinalizeContext(&ctx);
	 free(input_data);
	 free(digest);
	 if (signature)
		 free(signature);
	 return 0;
 }
 