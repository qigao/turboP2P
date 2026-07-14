# =============================================================================
# P2P Examples (Good Taste Design)
# =============================================================================

add_executable(p2p_client p2p_client.c)
target_link_libraries(
  p2p_client PRIVATE p2p TurboUtils::Core TurboNet::CoroNet 
                     OpenSSL::Crypto)
set_property(TARGET p2p_client PROPERTY FOLDER "p2p/examples")

add_executable(p2p_minio_s3 p2p_minio_s3.c)
target_link_libraries(
  p2p_minio_s3 PRIVATE p2p TurboUtils::Core TurboNet::CoroNet
  TurboHttp::Iris TurboUtils::Mustache TurboUtils::Parser
    OpenSSL::Crypto)
set_property(TARGET p2p_minio_s3 PROPERTY FOLDER "p2p/examples")
