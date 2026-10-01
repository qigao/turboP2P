#ifndef TURBOP2P_P2P_EXPORT_H
#define TURBOP2P_P2P_EXPORT_H

#if defined(_WIN32)
  #if defined(P2P_BUILDING_LIBRARY)
    #define P2P_API __declspec(dllexport)
  #else
    #define P2P_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define P2P_API __attribute__((visibility("default")))
#else
  #define P2P_API
#endif

#endif /* TURBOP2P_P2P_EXPORT_H */
