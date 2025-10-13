# Main component CMakeLists.txt

idf_component_register(
        SRC_DIRS "."
        INCLUDE_DIRS "."
    )

# Get firmware version from environment variable, default to "0.0.0-dev"
if(DEFINED ENV{FIRMWARE_VERSION})
    set(FIRMWARE_VERSION $ENV{FIRMWARE_VERSION})
else()
    set(FIRMWARE_VERSION "0.0.0-dev")
endif()

message(STATUS "Building firmware version: ${FIRMWARE_VERSION}")

# Generate version.h header file
# Note: Must be done AFTER idf_component_register because COMPONENT_DIR is set by it
configure_file(
    "${COMPONENT_DIR}/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    @ONLY
)

# Add the build directory to include path so version.h can be found
target_include_directories(${COMPONENT_LIB} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

# Force rebuild when version.h changes by adding it as a dependency
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version_force_rebuild.stamp
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/version_force_rebuild.stamp
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/version.h
    COMMENT "Triggering rebuild due to version change"
)
add_custom_target(version_rebuild DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/version_force_rebuild.stamp)
add_dependencies(${COMPONENT_LIB} version_rebuild)
