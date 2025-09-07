# Find required packages for AI enhancements
find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)
find_package(jsoncpp REQUIRED)

# Set CURL variables if not found by find_package
if(NOT CURL_FOUND)
    pkg_check_modules(CURL REQUIRED libcurl)
endif()

# Include directories
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${jsoncpp_INCLUDE_DIRS})

# Link directories
link_directories(${CURL_LIBRARY_DIRS})
link_directories(${jsoncpp_LIBRARY_DIRS})
