// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

 #ifndef __ACIPHER_TA_H__
 #define __ACIPHER_TA_H__
 
 /* UUID of the acipher example trusted application */
 #define TA_ACIPHER_UUID \
     { 0xa734eed9, 0xd6a1, 0x4244, { \
         0xaa, 0x50, 0x7c, 0x99, 0x71, 0x9e, 0x7b, 0x7b } }
 
 /*
  * Command IDs:
  *
  * TA_ACIPHER_CMD_GEN_KEY:
  *   in: params[0].value.a  存放密钥长度
  *
  * TA_ACIPHER_CMD_ENCRYPT:
  *   in:  params[1].memref  明文输入
  *   out: params[2].memref  密文输出
  *
  * TA_ACIPHER_CMD_SIGN:
  *   in:  params[0].memref  待签名数据（通常为摘要）
  *   out: params[1].memref  签名数据输出
  *
  * TA_ACIPHER_CMD_VERIFY:
  *   in:  params[0].memref  待验证数据（通常为摘要）
  *   in:  params[1].memref  签名数据
  *   out: params[2].value.a  验证结果 (1 表示签名有效，0 表示签名无效)
  *
  * TA_ACIPHER_CMD_DIGEST:
  *   in:  params[0].memref  待计算摘要的数据
  *   out: params[1].memref  摘要输出（例如使用SHA-256，固定32字节）
  */
 #define TA_ACIPHER_CMD_GEN_KEY    0
 #define TA_ACIPHER_CMD_ENCRYPT    1
 #define TA_ACIPHER_CMD_SIGN       2
 #define TA_ACIPHER_CMD_VERIFY     3
 #define TA_ACIPHER_CMD_DIGEST     4
 
 #endif /* __ACIPHER_TA_H__ */
 