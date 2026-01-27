#include "vivaldi.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

/* =============================================================================
 * Initialization
 * ============================================================================= */

void vivaldi_init(vivaldi_coord_t *coord) {
    if (!coord) return;

    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        coord->coords[i] = 0.0;
    }
    coord->height = 0.0;
    coord->error = VIVALDI_MAX_ERROR;
}

/* =============================================================================
 * Distance Calculation
 * ============================================================================= */

double vivaldi_distance(const vivaldi_coord_t *a, const vivaldi_coord_t *b) {
    if (!a || !b) return 0.0;

    double sum = 0.0;
    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        double diff = a->coords[i] - b->coords[i];
        sum += diff * diff;
    }

    /* Add height components */
    double dist = sqrt(sum) + a->height + b->height;
    return dist;
}

double vivaldi_estimate_rtt(const vivaldi_coord_t *a, const vivaldi_coord_t *b) {
    return vivaldi_distance(a, b);
}

/* =============================================================================
 * Coordinate Update (Spring-Mass Model)
 * ============================================================================= */

void vivaldi_update(vivaldi_coord_t *local, const vivaldi_coord_t *remote, double rtt_ms) {
    if (!local || !remote || rtt_ms <= 0) return;

    /* Calculate current estimated RTT */
    double estimated = vivaldi_distance(local, remote);

    /* Error between measured and estimated */
    double rtt_error = rtt_ms - estimated;

    /* Relative error for this sample */
    double relative_error = fabs(rtt_error) / rtt_ms;
    if (relative_error > 1.0) relative_error = 1.0;

    /* Weight based on both nodes' confidence */
    double weight = local->error / (local->error + remote->error);

    /* Update error estimate (exponential moving average) */
    local->error = relative_error * VIVALDI_CE * weight +
                   local->error * (1.0 - VIVALDI_CE * weight);

    /* Clamp error */
    if (local->error < VIVALDI_MIN_ERROR) local->error = VIVALDI_MIN_ERROR;
    if (local->error > VIVALDI_MAX_ERROR) local->error = VIVALDI_MAX_ERROR;

    /* Calculate movement step */
    double step = VIVALDI_CC * weight;

    /* Direction vector from local to remote */
    double dir[VIVALDI_DIMENSIONS];
    double dir_len = 0.0;
    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        dir[i] = remote->coords[i] - local->coords[i];
        dir_len += dir[i] * dir[i];
    }
    dir_len = sqrt(dir_len);

    /* Avoid division by zero */
    if (dir_len < 0.0001) {
        /* Nodes at same position, add random jitter */
        for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
            dir[i] = ((double)rand() / RAND_MAX) - 0.5;
        }
        dir_len = 1.0;
    }

    /* Normalize direction */
    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        dir[i] /= dir_len;
    }

    /* Move coordinate based on error */
    /* If rtt_error > 0: measured RTT > estimated, push apart */
    /* If rtt_error < 0: measured RTT < estimated, pull together */
    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        local->coords[i] += step * rtt_error * dir[i];
    }

    /* Update height (always positive, handles triangle inequality violations) */
    double height_delta = step * rtt_error;
    if (height_delta > 0) {
        /* Only increase height when we underestimate RTT */
        local->height += height_delta * 0.1;
    } else {
        /* Slowly decay height */
        local->height *= 0.99;
    }
    if (local->height < 0) local->height = 0;
}

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

int vivaldi_is_converged(const vivaldi_coord_t *coord, double threshold) {
    if (!coord) return 0;
    return coord->error < threshold;
}

void vivaldi_copy(vivaldi_coord_t *dst, const vivaldi_coord_t *src) {
    if (!dst || !src) return;
    memcpy(dst, src, sizeof(vivaldi_coord_t));
}

/* =============================================================================
 * Serialization
 * ============================================================================= */

int vivaldi_serialize(const vivaldi_coord_t *coord, uint8_t *buf) {
    if (!coord || !buf) return -1;

    uint8_t *p = buf;

    /* Write coordinates */
    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        memcpy(p, &coord->coords[i], sizeof(double));
        p += sizeof(double);
    }

    /* Write height */
    memcpy(p, &coord->height, sizeof(double));
    p += sizeof(double);

    /* Write error */
    memcpy(p, &coord->error, sizeof(double));
    p += sizeof(double);

    return (int)(p - buf);
}

int vivaldi_deserialize(vivaldi_coord_t *coord, const uint8_t *buf) {
    if (!coord || !buf) return -1;

    const uint8_t *p = buf;

    /* Read coordinates */
    for (int i = 0; i < VIVALDI_DIMENSIONS; i++) {
        memcpy(&coord->coords[i], p, sizeof(double));
        p += sizeof(double);
    }

    /* Read height */
    memcpy(&coord->height, p, sizeof(double));
    p += sizeof(double);

    /* Read error */
    memcpy(&coord->error, p, sizeof(double));
    p += sizeof(double);

    return (int)(p - buf);
}
