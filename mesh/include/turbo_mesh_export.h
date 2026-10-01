#ifndef TURBOP2P_MESH_EXPORT_H
#define TURBOP2P_MESH_EXPORT_H

#if defined(_WIN32)
  #if defined(MESH_BUILDING_LIBRARY)
    #define MESH_API __declspec(dllexport)
  #else
    #define MESH_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define MESH_API __attribute__((visibility("default")))
#else
  #define MESH_API
#endif

#endif /* TURBOP2P_MESH_EXPORT_H */
