/*
 * replay_client.c
 *
 * A simple C program that uses the OP‑TEE TEE Client API to
 * call the Replay TA (pseudo‑TA) and run the full Ethos‑U replay.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2025 Rejoice
 */

 #include <err.h>
 #include <stdio.h>
 #include <string.h>
 
 /* OP‑TEE TEE client API */
 #include <tee_client_api.h>
 
 /* Replay TA UUID and command IDs */
 #include "replay_ta.h"
 
 int main(void)
 {
	 TEEC_Result    res;
	 TEEC_Context   ctx;
	 TEEC_Session   sess;
	 TEEC_Operation op;
	 uint32_t       err_origin;
	 TEEC_UUID      uuid = TA_REPLAY_UUID;
 
	 /* 1. 创建 TEE Context */
	 res = TEEC_InitializeContext(NULL, &ctx);
	 if (res != TEEC_SUCCESS)
		 errx(1, "TEEC_InitializeContext failed: 0x%x", res);
 
	 /* 2. 打开到 Replay TA 的会话 */
	 res = TEEC_OpenSession(&ctx, &sess, &uuid,
							TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	 if (res != TEEC_SUCCESS)
		 errx(1, "TEEC_OpenSession failed: 0x%x, origin 0x%x",
			  res, err_origin);
 
	 /* 3. 调用 TA_REPLAY_CMD_RUN，无参数 */
	 memset(&op, 0, sizeof(op));
	 op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
									  TEEC_NONE,
									  TEEC_NONE,
									  TEEC_NONE);
 
	 printf("Invoking Replay TA to run Ethos‑U replay...\n");
	 res = TEEC_InvokeCommand(&sess,
							  TA_REPLAY_CMD_RUN,
							  &op, &err_origin);
	 if (res != TEEC_SUCCESS)
		 errx(1, "TEEC_InvokeCommand failed: 0x%x, origin 0x%x",
			  res, err_origin);
 
	 printf("Replay TA completed successfully.\n");
 
	 /* 4. 关闭会话并释放资源 */
	 TEEC_CloseSession(&sess);
	 TEEC_FinalizeContext(&ctx);
	 return 0;
 }
 