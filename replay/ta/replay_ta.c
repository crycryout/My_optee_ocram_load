/* SPDX-License-Identifier: BSD-2-Clause
 *
 * replay_ta.c
 *
 * 普通 TA，用来打开到 replay_pta 的会话并下发 Run 命令
 */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include "replay_ta.h"

/* 把宏 TA_REPLAY_UUID 展开成一个真正的变量，才能取地址传给 OpenTASession */
static const TEE_UUID replay_pta_uuid = TA_REPLAY_UUID;

/* TA 创建时调用 */
TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("Replay TA CreateEntryPoint");
    return TEE_SUCCESS;
}

/* TA 销毁时调用 */
void TA_DestroyEntryPoint(void)
{
    DMSG("Replay TA DestroyEntryPoint");
}

/* 打开会话时调用 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    (void)params; (void)sess_ctx;
    DMSG("Replay TA session opened");
    return TEE_SUCCESS;
}

/* 关闭会话时调用 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
    DMSG("Replay TA session closed");
}

/* 真正执行 replay 的函数 */
static TEE_Result run_replay(uint32_t param_types, TEE_Param params[4])
{
    uint32_t origin = TEE_ORIGIN_API;
    TEE_TASessionHandle pta_sess = TEE_HANDLE_NULL;
    TEE_Result res;

    /* 只接受无参数调用 */
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    (void)params;

    /* 1) 打开到 replay PTA 的会话 */
    res = TEE_OpenTASession(&replay_pta_uuid,
                            TEE_LOGIN_PUBLIC,
                            TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE),
                            NULL,      /* no connection data */
                            &pta_sess,
                            &origin);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_OpenTASession failed: 0x%x origin %u", res, origin);
        return res;
    }

    /* 2) 发 “REPLAY_CMD_RUN” 命令给 PTA */
    res = TEE_InvokeTACommand(pta_sess,
                              TEE_TIMEOUT_INFINITE,
                              TA_REPLAY_CMD_RUN,
                              TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE),
                              NULL,
                              &origin);
    if (res != TEE_SUCCESS)
        EMSG("TEE_InvokeTACommand(REPLAY_CMD_RUN) failed: 0x%x origin %u", res, origin);

    /* 3) 关会话 */
    TEE_CloseTASession(pta_sess);
    return res;
}

/* TA 收到客户端调用时的入口 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __maybe_unused,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)sess_ctx;
    switch (cmd_id) {
    case TA_REPLAY_CMD_RUN:
        return run_replay(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
