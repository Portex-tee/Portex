cmake_minimum_required(VERSION 3.5)
project(log_manager)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../cmake)
find_package(SGX REQUIRED)

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
add_enclave_library(enclave SRCS ${E_SRCS} EDL isv_enclave/isv_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(enclave KEY isv_enclave/isv_enclave_private.pem CONFIG isv_enclave/isv_enclave.config.xml)

set(SRCS isv_app/isv_app.cpp)
add_untrusted_executable(LM SRCS ${SRCS} EDL isv_enclave/isv_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_dependencies(LM enclave-sign)

target_link_libraries(LM libcryptopp.a libpbc.a libgmp.a libssl.a libcrypto.a service_provider libpthread.a -lm -lc -lstdc++ ${LIB_SAMP})