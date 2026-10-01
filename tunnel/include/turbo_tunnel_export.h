#ifndef TURBOP2P_TUNNEL_EXPORT_H
#define TURBOP2P_TUNNEL_EXPORT_H

#if defined(_WIN32)
  #if defined(TUNNEL_BUILDING_LIBRARY)
    #define TUNNEL_API __declspec(dllexport)
  #else
    #define TUNNEL_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define TUNNEL_API __attribute__((visibility("default")))
#else
  #define TUNNEL_API
#endif

#endif /* TURBOP2P_TUNNEL_EXPORT_H */
