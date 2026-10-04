#ifndef P2P_PEER_CORONET_H
#define P2P_PEER_CORONET_H
#include "peer.h"
#include <CoroNet/turbo_callbacks.h>
int p2p_peer_stream_recv(void *handle, const mem_slice_t *slice, void *peer_ctx);
void p2p_peer_stream_close(void *handle);
void p2p_peer_stream_connect(void *handle, int status, void *arg);
#endif
