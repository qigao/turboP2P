# =============================================================================
# P2P Examples (Good Taste Design)
# =============================================================================

add_executable(p2p_client p2p_client.c)
target_link_libraries(
  p2p_client PRIVATE p2p TurboNet::Utils TurboNet::Core libuv::uv
                     OpenSSL::Crypto)
set_property(TARGET p2p_client PROPERTY FOLDER "p2p/examples")

add_executable(p2p_minio_s3 p2p_minio_s3.c)
target_link_libraries(
  p2p_minio_s3 PRIVATE p2p TurboNet::Utils TurboNet::Core 
  TurboNet::Iris TurboNet::Mustache TurboNet::Parser
   libuv::uv OpenSSL::Crypto)
set_property(TARGET p2p_minio_s3 PROPERTY FOLDER "p2p/examples")
