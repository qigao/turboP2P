#include <cnet/cnet.h>
#include <cmeta/abi.h>
#include <cmeta/cmeta.h>
#include <cflow/cflow.h>
#include <salts/plugin.h>
#include <data_bind_method_plan.h>

#include <stdio.h>
#include <stdlib.h>

#if !defined(CNET_STOP_DRAIN_CONTRACT_VERSION) || CNET_STOP_DRAIN_CONTRACT_VERSION < 1u
#error "TurboP2P requires the current CNet stop/drain contract"
#endif

int main(void) {
  const uint32_t runtime_abi = cmeta_reflection_abi_version();
  if (runtime_abi != CMETA_REFLECTION_ABI_VERSION) {
    fprintf(stderr, "CMeta header/runtime ABI mismatch: %u != %u\n",
            (unsigned)runtime_abi, (unsigned)CMETA_REFLECTION_ABI_VERSION);
    return EXIT_FAILURE;
  }
  printf("SDK headers and CMeta ABI %u qualified; CNet terminal API %u\n",
         (unsigned)runtime_abi, (unsigned)CNET_PACKET_TERMINAL_API_VERSION);
  return EXIT_SUCCESS;
}
