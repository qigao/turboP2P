# Sanitizer configuration module
# Supports: AddressSanitizer, UndefinedBehaviorSanitizer, ThreadSanitizer, LeakSanitizer, MemorySanitizer

# Options for enabling sanitizers
option(ENABLE_SANITIZER_ADDRESS "Enable AddressSanitizer" OFF)
option(ENABLE_SANITIZER_UNDEFINED "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_SANITIZER_LEAK "Enable LeakSanitizer" OFF)
option(ENABLE_SANITIZER_THREAD "Enable ThreadSanitizer" OFF)
option(ENABLE_SANITIZER_MEMORY "Enable MemorySanitizer (Clang only)" OFF)

# Function to add sanitizer flags to a target
function(add_sanitizers target_name)
    set(SANITIZER_FLAGS "")
    set(SANITIZER_LINK_FLAGS "")
    
    # Check for conflicting sanitizers
    if(ENABLE_SANITIZER_THREAD AND (ENABLE_SANITIZER_ADDRESS OR ENABLE_SANITIZER_LEAK OR ENABLE_SANITIZER_MEMORY))
        message(FATAL_ERROR "ThreadSanitizer cannot be combined with AddressSanitizer, LeakSanitizer, or MemorySanitizer")
    endif()
    
    if(ENABLE_SANITIZER_MEMORY AND (ENABLE_SANITIZER_ADDRESS OR ENABLE_SANITIZER_LEAK OR ENABLE_SANITIZER_THREAD))
        message(FATAL_ERROR "MemorySanitizer cannot be combined with other sanitizers")
    endif()
    
    # AddressSanitizer
    if(ENABLE_SANITIZER_ADDRESS)
        message(STATUS "AddressSanitizer enabled for target: ${target_name}")
        if(MSVC)
            # MSVC ASan requires /fsanitize=address compiler flag
            target_compile_options(${target_name} PRIVATE /fsanitize=address)
            # No separate link flag needed for modern MSVC if using the right runtime, 
            # but sometimes /fsanitize=address is needed at link time too or is implied.
            # Visual Studio usually handles the linking part automatically if the flag is on.
        else()
            list(APPEND SANITIZER_FLAGS -fsanitize=address)
            list(APPEND SANITIZER_FLAGS -fno-omit-frame-pointer)
            list(APPEND SANITIZER_FLAGS -fno-optimize-sibling-calls)
            list(APPEND SANITIZER_LINK_FLAGS -fsanitize=address)
        endif()
    endif()
    
    # UndefinedBehaviorSanitizer
    if(ENABLE_SANITIZER_UNDEFINED)
        message(STATUS "UndefinedBehaviorSanitizer enabled for target: ${target_name}")
        if(MSVC)
            # MSVC doesn't support UBSan as of now
            message(WARNING "UndefinedBehaviorSanitizer is not supported by MSVC")
        else()
            list(APPEND SANITIZER_FLAGS -fsanitize=undefined)
            list(APPEND SANITIZER_FLAGS -fno-omit-frame-pointer)
            list(APPEND SANITIZER_LINK_FLAGS -fsanitize=undefined)
            
            # Additional UBSan options for better diagnostics
            if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                list(APPEND SANITIZER_FLAGS -fsanitize=integer)
                list(APPEND SANITIZER_FLAGS -fsanitize=nullability)
                list(APPEND SANITIZER_LINK_FLAGS -fsanitize=integer)
                list(APPEND SANITIZER_LINK_FLAGS -fsanitize=nullability)
            endif()
        endif()
    endif()
    
    # LeakSanitizer
    if(ENABLE_SANITIZER_LEAK)
        message(STATUS "LeakSanitizer enabled for target: ${target_name}")
        if(MSVC)
            message(WARNING "LeakSanitizer is not supported by MSVC")
        else()
            list(APPEND SANITIZER_FLAGS -fsanitize=leak)
            list(APPEND SANITIZER_FLAGS -fno-omit-frame-pointer)
            list(APPEND SANITIZER_LINK_FLAGS -fsanitize=leak)
        endif()
    endif()
    
    # ThreadSanitizer
    if(ENABLE_SANITIZER_THREAD)
        message(STATUS "ThreadSanitizer enabled for target: ${target_name}")
        if(MSVC)
            message(WARNING "ThreadSanitizer is not supported by MSVC")
        else()
            list(APPEND SANITIZER_FLAGS -fsanitize=thread)
            list(APPEND SANITIZER_FLAGS -fno-omit-frame-pointer)
            list(APPEND SANITIZER_LINK_FLAGS -fsanitize=thread)
        endif()
    endif()
    
    # MemorySanitizer (Clang only)
    if(ENABLE_SANITIZER_MEMORY)
        message(STATUS "MemorySanitizer enabled for target: ${target_name}")
        if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            message(FATAL_ERROR "MemorySanitizer is only supported by Clang")
        endif()
        if(MSVC)
            message(WARNING "MemorySanitizer is not supported by MSVC")
        else()
            list(APPEND SANITIZER_FLAGS -fsanitize=memory)
            list(APPEND SANITIZER_FLAGS -fno-omit-frame-pointer)
            list(APPEND SANITIZER_FLAGS -fsanitize-memory-track-origins)
            list(APPEND SANITIZER_LINK_FLAGS -fsanitize=memory)
        endif()
    endif()
    
    # Apply flags to target
    if(SANITIZER_FLAGS)
        target_compile_options(${target_name} PRIVATE ${SANITIZER_FLAGS})
        target_link_options(${target_name} PRIVATE ${SANITIZER_LINK_FLAGS})
        
        # Set runtime environment variables for better output
        if(NOT MSVC)
            set_target_properties(${target_name} PROPERTIES
                VS_DEBUGGER_ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:check_initialization_order=1:strict_init_order=1"
            )
        endif()
    endif()
endfunction()

# Global sanitizer setup (applies to all targets)
if(ENABLE_SANITIZER_ADDRESS OR ENABLE_SANITIZER_UNDEFINED OR ENABLE_SANITIZER_LEAK OR 
   ENABLE_SANITIZER_THREAD OR ENABLE_SANITIZER_MEMORY)
    
    message(STATUS "=== Sanitizers Configuration ===")
    message(STATUS "AddressSanitizer: ${ENABLE_SANITIZER_ADDRESS}")
    message(STATUS "UndefinedBehaviorSanitizer: ${ENABLE_SANITIZER_UNDEFINED}")
    message(STATUS "LeakSanitizer: ${ENABLE_SANITIZER_LEAK}")
    message(STATUS "ThreadSanitizer: ${ENABLE_SANITIZER_THREAD}")
    message(STATUS "MemorySanitizer: ${ENABLE_SANITIZER_MEMORY}")
    message(STATUS "================================")
    
    # Disable optimizations for better stack traces
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(NOT MSVC)
            add_compile_options(-O1 -g)
        endif()
    endif()
endif()
