#ifndef TURBO_P2P_MESH_MGMT_RECORD_EPOCH_H
#define TURBO_P2P_MESH_MGMT_RECORD_EPOCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Persistently reserve one non-zero record epoch before a signed record can
 * become externally visible. A successful reservation must never be returned
 * again, including after process restart.
 */
typedef int (*mesh_mgmt_record_epoch_allocate_fn)(void *context,
                                                   uint64_t *out_record_epoch);

#ifdef __cplusplus
}
#endif

#endif
