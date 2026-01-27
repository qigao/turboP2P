/**
 * P2P Transfer Resume (Stub)
 */
#ifndef P2P_RESUME_H
#define P2P_RESUME_H

#include <string.h>

/* Forward declare */
struct p2p_transfer_s;

/* Stub functions - not implemented yet */
static inline int p2p_transfer_save_state(struct p2p_transfer_s *transfer) {
    (void)transfer;
    return 0;
}

static inline int p2p_transfer_load_state(struct p2p_transfer_s *transfer, const char *resume_path) {
    (void)transfer; (void)resume_path;
    return -1;
}

static inline void p2p_transfer_delete_state(struct p2p_transfer_s *transfer) {
    (void)transfer;
}

static inline void p2p_resume_path_from_filepath(const char *filepath, char *resume_path, size_t size) {
    if (resume_path && size > 0) {
        strncpy(resume_path, filepath, size - 1);
        resume_path[size - 1] = '\0';
        /* Append .resume extension */
        size_t len = strlen(resume_path);
        if (len + 8 < size) {
            strcat(resume_path, ".resume");
        }
    }
}

static inline void p2p_resume_save(struct p2p_transfer_s *transfer) {
    p2p_transfer_save_state(transfer);
}

#endif /* P2P_RESUME_H */
