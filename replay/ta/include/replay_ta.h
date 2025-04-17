/* replay_ta.h */
#ifndef REPLAY_TA_H
#define REPLAY_TA_H


/*
 * 这个 UUID 要和你在 pseudo‑TA (replay_pta.c) 里用的完全一样，
 * 我用的是 uuidgen 生成的 da782f75‑bc08‑4e23‑becd‑3be026c8a146
 */
#define TA_REPLAY_UUID \
    { 0xb6c53aba, 0x9669, 0x4668, \
      { 0xa7, 0xf2, 0x20, 0x56, 0x29, 0xd0, 0x0f, 0x86 } }

/* 伪TA里定义的命令号 */
#define TA_REPLAY_CMD_RUN    0

#endif /* REPLAY_TA_H */
