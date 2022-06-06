cmake_minimum_required (VERSION 3.5.1)

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac
###
### In order to create PALISADE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: PALISADEpke_static.a, PALISADEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"

project(demo CXX)
set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")

set(CMAKE_CXX_STANDARD 11)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(Palisade)

set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${PALISADE_INCLUDE} )
include_directories( ${PALISADE_INCLUDE}/third-party )
include_directories( ${PALISADE_INCLUDE}/core )
include_directories( ${PALISADE_INCLUDE}/pke )
include_directories( ${PALISADE_INCLUDE}/binfhe )
include_directories(third-party/google-benchmark EXCLUDE_FROM_ALL)

### add directories for other PALISADE modules as needed for your project
### build the google benchmark handlers (just the parts we need)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
#add_subdirectory(benchmark)

link_directories( ${PALISADE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${PALISADE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${PALISADE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )
    link_libraries( ${PALISADE_SHARED_LIBRARIES} )
endif()

link_directories(./tiny)

### ADD YOUR EXECUTABLE(s) HERE
add_executable( demo 
                helloWorld.cpp )
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )
