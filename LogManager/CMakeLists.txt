cmake_minimum_required(VERSION 3.5)
project(LogManager)

include(CheckIncludeFileCXX)

check_include_file_cxx(any HAS_ANY)
check_include_file_cxx(string_view HAS_STRING_VIEW)
check_include_file_cxx(coroutine HAS_COROUTINE)

set(CMAKE_CXX_STANDARD 14)


set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../cmake)
find_package(SGX REQUIRED)
find_package(Drogon CONFIG REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

include_directories(${SGX_INCLUDE_DIR} service_provider sample_libcrypto isv_app isv_enclave)

set(EDL_SEARCH_PATHS isv_enclave)

set(LDS isv_enclave/isv_enclave.lds)

set(E_SRCS isv_enclave/isv_enclave.cpp)

file(GLOB U_SRCS service_provider/*.cpp)
add_library(service_provider STATIC ${U_SRCS})

file(GLOB LIB_SAMP sample_libcrypto/libsample_libcrypto.so)

#file(GLOB T_SRCS LocalAttestationCode/*.c*)
#add_trusted_library(LocalAttestationLib SRCS "${T_SRCS}" EDL LocalAttestationCode/LocalAttestationCode.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

#add_trusted_library(trusted_lib SRCS ${T_SRCS} EDL isv_enclave/isv_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_enclave_library(enclave SRCS ${E_SRCS} EDL isv_enclave/isv_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS} USE_SGXSSL 1)
enclave_sign(enclave KEY isv_enclave/isv_enclave_private.pem CONFIG isv_enclave/isv_enclave.config.xml)

set(SRCS isv_app/isv_app.cpp)
add_untrusted_executable(${PROJECT_NAME} SRCS ${SRCS} EDL isv_enclave/isv_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_dependencies(${PROJECT_NAME} enclave-sign)

target_link_libraries(${PROJECT_NAME} -lcryptopp -lpbc -lgmp service_provider -lm -lc -lstdc++ ${LIB_SAMP})

# ##############################################################################
# If you include the drogon source code locally in your project, use this method
# to add drogon
# add_subdirectory(drogon)
# target_link_libraries(${PROJECT_NAME} PRIVATE drogon)
#
# and comment out the following lines
target_link_libraries(${PROJECT_NAME} Drogon::Drogon)

# ##############################################################################

message(STATUS "use c++14")
find_package(Boost 1.61.0 REQUIRED)
target_link_libraries(${PROJECT_NAME} Boost::boost)

aux_source_directory(controllers CTL_SRC)
aux_source_directory(filters FILTER_SRC)
aux_source_directory(plugins PLUGIN_SRC)
aux_source_directory(models MODEL_SRC)

drogon_create_views(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/views
        ${CMAKE_CURRENT_BINARY_DIR})


target_include_directories(${PROJECT_NAME}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/models)
target_sources(${PROJECT_NAME}
        PRIVATE
        ${SRC_DIR}
        ${CTL_SRC}
        ${FILTER_SRC}
        ${PLUGIN_SRC}
        ${MODEL_SRC})
# ##############################################################################
# uncomment the following line for dynamically loading views
# set_property(TARGET ${PROJECT_NAME} PROPERTY ENABLE_EXPORTS ON)

# ##############################################################################

