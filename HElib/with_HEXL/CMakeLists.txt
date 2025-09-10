cmake_minimum_required(VERSION 3.10)
project(helib_experiments)

set(CMAKE_CXX_STANDARD 17)

# Path to your local HElib build with HEXL
set(HELIB_ROOT "/home/prashant-rawat/HElib_benchmarking/HElib_with_HEXL")

# Include headers
include_directories(${HELIB_ROOT}/include)

# Link libraries
link_directories(${HELIB_ROOT}/lib)

# Executables
add_executable(run_scalar scalar_experiment.cpp)
target_link_libraries(run_scalar helib ntl gmp pthread)

add_executable(run_vector vector_experiment.cpp)
target_link_libraries(run_vector helib ntl gmp pthread)

