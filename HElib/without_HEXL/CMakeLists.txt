cmake_minimum_required(VERSION 3.10)
project(helib_experiments)

set(CMAKE_CXX_STANDARD 17)

find_package(helib REQUIRED)

add_executable(run_scalar scalar_experiment.cpp)
target_link_libraries(run_scalar helib)

add_executable(run_vector vector_experiment.cpp)
target_link_libraries(run_vector helib)
