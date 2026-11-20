/**
 * @file c2000_studio_agent.h
 * @brief Phase-B Firmware-Cooperative Tuning Mailbox (.tunebox) & 20 kHz DLOG Ring (.dlog)
 *        for TI TMS320F28069M and TMS320F28388D (C28x EABI & COFF ABI compatible, pure C99).
 *
 * Key Guarantees:
 *  1. Atomic PWM-boundary (CTR=ZERO) parameter swaps via CRC32 + sequence handshake (seq_host/seq_ack).
 *  2. Firmware-side per-ISR slew-rate limiting and min/max clamping (no instantaneous step shocks).
 *  3. Optional host-lease dead-man watchdog that smoothly ramps back to safe defaults if JTAG stalls.
 *  4. Bumpless PI/PID integral-gain rescale helper.
 *  5. Isolated-bank deterministic ISR-rate DLOG ring buffer with Freeze-on-Trigger & lockless sequence tags.
 */

#ifndef C2000_STUDIO_AGENT_H
#define C2000_STUDIO_AGENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef C2000_TUNE_MAX_PARAMS
#define C2000_TUNE_MAX_PARAMS 16U
#endif

#ifndef C2000_DLOG_MAX_CH
#define C2000_DLOG_MAX_CH 4U
#endif

#ifndef C2000_DLOG_CAPACITY
#define C2000_DLOG_CAPACITY 256U /* Must be a power of two */
#endif

#define C2000_TUNE_MAGIC 0x54554E45UL /* 'TUNE' */
#define C2000_DLOG_MAGIC 0x444C4F47UL /* 'DLOG' */
#define C2000_AGENT_VERSION 2U

#define C2000_TUNE_FLAG_LEASE_ARMED     (1UL << 0)
#define C2000_TUNE_FLAG_FAILSAFE_ACTIVE (1UL << 1)
#define C2000_TUNE_FLAG_CRC_ERROR       (1UL << 2)
#define C2000_TUNE_FLAG_SLEWING         (1UL << 3)

#define C2000_DLOG_TRIG_FREE          0U
#define C2000_DLOG_TRIG_EDGE_RISE     1U
#define C2000_DLOG_TRIG_EDGE_FALL     2U
#define C2000_DLOG_TRIG_ON_TUNE_WRITE 3U

#define C2000_DLOG_STATE_IDLE      0U
#define C2000_DLOG_STATE_ARMED     1U
#define C2000_DLOG_STATE_POST_TRIG 2U
#define C2000_DLOG_STATE_FROZEN    3U

typedef struct C2000TuneMailbox_s {
    uint32_t magic;
    uint32_t version;
    uint32_t build_hash32;
    uint32_t param_count;

    volatile uint32_t seq_host;
    volatile uint32_t seq_ack;
    volatile uint32_t staged_crc32;
    volatile uint32_t host_lease_feed;

    uint32_t lease_timeout_ticks;
    uint32_t lease_ticks_rem;
    uint32_t last_lease_feed;
    volatile uint32_t status_flags;

    volatile float staged[C2000_TUNE_MAX_PARAMS];
    float target[C2000_TUNE_MAX_PARAMS];
    float active[C2000_TUNE_MAX_PARAMS];
    float safe_default[C2000_TUNE_MAX_PARAMS];
    float min_val[C2000_TUNE_MAX_PARAMS];
    float max_val[C2000_TUNE_MAX_PARAMS];
    float slew_per_tick[C2000_TUNE_MAX_PARAMS];
} C2000TuneMailbox_t;

typedef struct C2000DlogBuffer_s {
    uint32_t magic;
    uint32_t version;
    float sample_hz;
    uint32_t num_channels;
    uint32_t capacity;

    volatile uint32_t write_idx;
    volatile uint32_t seq_start;
    volatile uint32_t seq_end;

    volatile uint32_t trig_mode;
    volatile uint32_t trig_state;
    volatile uint32_t trig_channel;
    float trig_level;
    uint32_t post_trig_samples;
    uint32_t post_trig_rem;
    float prev_trig_sample;

    float samples[C2000_DLOG_CAPACITY * C2000_DLOG_MAX_CH];
} C2000DlogBuffer_t;

static inline uint32_t c2000_studio_float_bits(float v)
{
    union {
        float f;
        uint32_t u;
    } cvt;
    cvt.f = v;
    return cvt.u;
}

static inline uint32_t c2000_studio_crc32_words(const volatile float *words, uint32_t count)
{
    uint32_t crc = 0xFFFFFFFFUL;
    uint32_t i;
    for (i = 0U; i < count; ++i) {
        uint32_t w = c2000_studio_float_bits(words[i]);
        uint32_t b;
        for (b = 0U; b < 4U; ++b) {
            uint32_t byte_val = (w >> (b * 8U)) & 0xFFUL;
            uint32_t bit;
            crc ^= byte_val;
            for (bit = 0U; bit < 8U; ++bit) {
                if ((crc & 1UL) != 0UL) {
                    crc = (crc >> 1U) ^ 0xEDB88320UL;
                } else {
                    crc >>= 1U;
                }
            }
        }
    }
    return crc ^ 0xFFFFFFFFUL;
}

static inline float c2000_studio_clampf(float x, float lo, float hi)
{
    if (x < lo) {
        return lo;
    }
    if (x > hi) {
        return hi;
    }
    return x;
}

static inline float c2000_tune_bumpless_ki(float prev_ki, float new_ki, float integrator_state)
{
    if ((new_ki > 1e-9f) || (new_ki < -1e-9f)) {
        return integrator_state * (prev_ki / new_ki);
    }
    return integrator_state;
}

static inline void c2000_tune_init(
    C2000TuneMailbox_t *box,
    uint32_t build_hash32,
    uint32_t param_count,
    uint32_t lease_timeout_ticks)
{
    uint32_t i;
    if (param_count > C2000_TUNE_MAX_PARAMS) {
        param_count = C2000_TUNE_MAX_PARAMS;
    }
    box->magic = C2000_TUNE_MAGIC;
    box->version = C2000_AGENT_VERSION;
    box->build_hash32 = build_hash32;
    box->param_count = param_count;
    box->seq_host = 0UL;
    box->seq_ack = 0UL;
    box->staged_crc32 = 0UL;
    box->host_lease_feed = 0UL;
    box->last_lease_feed = 0UL;
    box->lease_timeout_ticks = lease_timeout_ticks;
    box->lease_ticks_rem = lease_timeout_ticks;
    box->status_flags = (lease_timeout_ticks > 0UL) ? C2000_TUNE_FLAG_LEASE_ARMED : 0UL;
    for (i = 0U; i < C2000_TUNE_MAX_PARAMS; ++i) {
        box->staged[i] = 0.0f;
        box->target[i] = 0.0f;
        box->active[i] = 0.0f;
        box->safe_default[i] = 0.0f;
        box->min_val[i] = -1e6f;
        box->max_val[i] = 1e6f;
        box->slew_per_tick[i] = 0.0f;
    }
}

static inline void c2000_tune_config_param(
    C2000TuneMailbox_t *box,
    uint32_t idx,
    float init_val,
    float safe_val,
    float min_v,
    float max_v,
    float slew_per_tick)
{
    if (idx >= box->param_count) {
        return;
    }
    init_val = c2000_studio_clampf(init_val, min_v, max_v);
    safe_val = c2000_studio_clampf(safe_val, min_v, max_v);
    box->staged[idx] = init_val;
    box->target[idx] = init_val;
    box->active[idx] = init_val;
    box->safe_default[idx] = safe_val;
    box->min_val[idx] = min_v;
    box->max_val[idx] = max_v;
    box->slew_per_tick[idx] = (slew_per_tick < 0.0f) ? 0.0f : slew_per_tick;
}

static inline uint16_t c2000_tune_isr_step(C2000TuneMailbox_t *box)
{
    uint16_t committed = 0U;
    uint32_t i;
    uint32_t n = box->param_count;
    uint32_t slewing = 0UL;

    if ((box->lease_timeout_ticks > 0UL) && ((box->status_flags & C2000_TUNE_FLAG_LEASE_ARMED) != 0UL)) {
        uint32_t feed = box->host_lease_feed;
        if (feed != box->last_lease_feed) {
            box->last_lease_feed = feed;
            box->lease_ticks_rem = box->lease_timeout_ticks;
            box->status_flags &= ~C2000_TUNE_FLAG_FAILSAFE_ACTIVE;
        } else if (box->lease_ticks_rem > 0UL) {
            box->lease_ticks_rem -= 1UL;
        } else {
            box->status_flags |= C2000_TUNE_FLAG_FAILSAFE_ACTIVE;
            for (i = 0U; i < n; ++i) {
                box->target[i] = box->safe_default[i];
            }
        }
    }

    {
        uint32_t host_seq = box->seq_host;
        if (host_seq != box->seq_ack) {
            uint32_t calc = c2000_studio_crc32_words(box->staged, n);
            if (calc == box->staged_crc32) {
                for (i = 0U; i < n; ++i) {
                    box->target[i] = c2000_studio_clampf(box->staged[i], box->min_val[i], box->max_val[i]);
                }
                box->status_flags &= ~(C2000_TUNE_FLAG_CRC_ERROR | C2000_TUNE_FLAG_FAILSAFE_ACTIVE);
                box->lease_ticks_rem = box->lease_timeout_ticks;
                committed = 1U;
            } else {
                box->status_flags |= C2000_TUNE_FLAG_CRC_ERROR;
            }
            box->seq_ack = host_seq;
        }
    }

    for (i = 0U; i < n; ++i) {
        float cur = box->active[i];
        float dst = box->target[i];
        float rate = box->slew_per_tick[i];
        if (rate <= 0.0f) {
            box->active[i] = dst;
        } else {
            float diff = dst - cur;
            if (diff > rate) {
                box->active[i] = cur + rate;
                slewing = C2000_TUNE_FLAG_SLEWING;
            } else if (diff < -rate) {
                box->active[i] = cur - rate;
                slewing = C2000_TUNE_FLAG_SLEWING;
            } else {
                box->active[i] = dst;
            }
        }
    }
    box->status_flags = (box->status_flags & ~C2000_TUNE_FLAG_SLEWING) | slewing;
    return committed;
}

static inline void c2000_dlog_init(C2000DlogBuffer_t *dlog, float sample_hz, uint32_t num_channels)
{
    if ((num_channels == 0U) || (num_channels > C2000_DLOG_MAX_CH)) {
        num_channels = C2000_DLOG_MAX_CH;
    }
    dlog->magic = C2000_DLOG_MAGIC;
    dlog->version = C2000_AGENT_VERSION;
    dlog->sample_hz = sample_hz;
    dlog->num_channels = num_channels;
    dlog->capacity = C2000_DLOG_CAPACITY;
    dlog->write_idx = 0UL;
    dlog->seq_start = 0UL;
    dlog->seq_end = 0UL;
    dlog->trig_mode = C2000_DLOG_TRIG_FREE;
    dlog->trig_state = C2000_DLOG_STATE_ARMED;
    dlog->trig_channel = 0UL;
    dlog->trig_level = 0.0f;
    dlog->post_trig_samples = (C2000_DLOG_CAPACITY * 3U) / 4U;
    dlog->post_trig_rem = dlog->post_trig_samples;
    dlog->prev_trig_sample = 0.0f;
}

static inline void c2000_dlog_push4(
    C2000DlogBuffer_t *dlog,
    float c0,
    float c1,
    float c2,
    float c3,
    uint16_t tune_committed_flag)
{
    uint32_t slot;
    uint32_t base;
    float trig_val;

    if (dlog->trig_state == C2000_DLOG_STATE_FROZEN) {
        return;
    }

    slot = dlog->write_idx & (C2000_DLOG_CAPACITY - 1U);
    base = slot * C2000_DLOG_MAX_CH;

    dlog->seq_start = dlog->seq_start + 1UL;
    dlog->samples[base + 0U] = c0;
    dlog->samples[base + 1U] = c1;
    dlog->samples[base + 2U] = c2;
    dlog->samples[base + 3U] = c3;
    dlog->write_idx = dlog->write_idx + 1UL;
    dlog->seq_end = dlog->seq_start;

    trig_val = (dlog->trig_channel == 0UL) ? c0
             : (dlog->trig_channel == 1UL) ? c1
             : (dlog->trig_channel == 2UL) ? c2 : c3;

    if (dlog->trig_state == C2000_DLOG_STATE_ARMED) {
        uint16_t fired = 0U;
        if ((dlog->trig_mode == C2000_DLOG_TRIG_EDGE_RISE) &&
            (dlog->prev_trig_sample < dlog->trig_level) && (trig_val >= dlog->trig_level)) {
            fired = 1U;
        } else if ((dlog->trig_mode == C2000_DLOG_TRIG_EDGE_FALL) &&
                   (dlog->prev_trig_sample > dlog->trig_level) && (trig_val <= dlog->trig_level)) {
            fired = 1U;
        } else if ((dlog->trig_mode == C2000_DLOG_TRIG_ON_TUNE_WRITE) && (tune_committed_flag != 0U)) {
            fired = 1U;
        }
        if (fired != 0U) {
            dlog->trig_state = C2000_DLOG_STATE_POST_TRIG;
            dlog->post_trig_rem = dlog->post_trig_samples;
        }
    } else if (dlog->trig_state == C2000_DLOG_STATE_POST_TRIG) {
        if (dlog->post_trig_rem > 0UL) {
            dlog->post_trig_rem -= 1UL;
        } else {
            dlog->trig_state = C2000_DLOG_STATE_FROZEN;
        }
    }
    dlog->prev_trig_sample = trig_val;
}

#ifdef __cplusplus
}
#endif

#endif /* C2000_STUDIO_AGENT_H */
