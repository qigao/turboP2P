/**
 * Vivaldi Coordinates - Distributed Latency Estimation
 *
 * Implements the Vivaldi algorithm for estimating network latency
 * using virtual coordinates in a multi-dimensional space.
 */
#ifndef P2P_VIVALDI_H
#define P2P_VIVALDI_H

#include <stdint.h>

/* Coordinate system parameters */
#ifndef VIVALDI_DIMENSIONS
#define VIVALDI_DIMENSIONS  4
#endif

#define VIVALDI_CC          0.25    /* Coordinate adjustment weight */
#define VIVALDI_CE          0.25    /* Error adjustment weight */
#define VIVALDI_MIN_ERROR   0.01    /* Minimum error bound */
#define VIVALDI_MAX_ERROR   1.0     /* Maximum error bound */

/* Use the vivaldi_coord_t from types.h if already defined */
#ifndef P2P_VIVALDI_COORD_DEFINED
#define P2P_VIVALDI_COORD_DEFINED
typedef struct {
    double coords[VIVALDI_DIMENSIONS];  /* Position in virtual space */
    double height;                       /* Height component (non-Euclidean) */
    double error;                        /* Estimation error (confidence) */
} vivaldi_coord_t;
#endif

/**
 * Initialize coordinate to origin
 */
void vivaldi_init(vivaldi_coord_t *coord);

/**
 * Calculate Euclidean distance between coordinates
 */
double vivaldi_distance(const vivaldi_coord_t *a, const vivaldi_coord_t *b);

/**
 * Estimate RTT between two coordinates (alias for distance)
 */
double vivaldi_estimate_rtt(const vivaldi_coord_t *a, const vivaldi_coord_t *b);

/**
 * Update local coordinate based on measured RTT to remote
 * Uses spring-mass model for coordinate adjustment
 */
void vivaldi_update(vivaldi_coord_t *local, const vivaldi_coord_t *remote, double rtt_ms);

/**
 * Check if coordinate has converged (error below threshold)
 */
int vivaldi_is_converged(const vivaldi_coord_t *coord, double threshold);

/**
 * Copy coordinate from src to dst
 */
void vivaldi_copy(vivaldi_coord_t *dst, const vivaldi_coord_t *src);

/**
 * Serialize coordinate to buffer
 * Returns bytes written, or -1 on error
 */
int vivaldi_serialize(const vivaldi_coord_t *coord, uint8_t *buf);

/**
 * Deserialize coordinate from buffer
 * Returns bytes read, or -1 on error
 */
int vivaldi_deserialize(vivaldi_coord_t *coord, const uint8_t *buf);

#endif /* P2P_VIVALDI_H */
