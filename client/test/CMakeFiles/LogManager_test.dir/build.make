# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /media/jojjiw/EX/ub-space/SGXAibeProject/client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /media/jojjiw/EX/ub-space/SGXAibeProject/client

# Include any dependencies generated for this target.
include test/CMakeFiles/LogManager_test.dir/depend.make

# Include the progress variables for this target.
include test/CMakeFiles/LogManager_test.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/LogManager_test.dir/flags.make

test/CMakeFiles/LogManager_test.dir/test_main.cc.o: test/CMakeFiles/LogManager_test.dir/flags.make
test/CMakeFiles/LogManager_test.dir/test_main.cc.o: test/test_main.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/media/jojjiw/EX/ub-space/SGXAibeProject/client/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object test/CMakeFiles/LogManager_test.dir/test_main.cc.o"
	cd /media/jojjiw/EX/ub-space/SGXAibeProject/client/test && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/LogManager_test.dir/test_main.cc.o -c /media/jojjiw/EX/ub-space/SGXAibeProject/client/test/test_main.cc

test/CMakeFiles/LogManager_test.dir/test_main.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/LogManager_test.dir/test_main.cc.i"
	cd /media/jojjiw/EX/ub-space/SGXAibeProject/client/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /media/jojjiw/EX/ub-space/SGXAibeProject/client/test/test_main.cc > CMakeFiles/LogManager_test.dir/test_main.cc.i

test/CMakeFiles/LogManager_test.dir/test_main.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/LogManager_test.dir/test_main.cc.s"
	cd /media/jojjiw/EX/ub-space/SGXAibeProject/client/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /media/jojjiw/EX/ub-space/SGXAibeProject/client/test/test_main.cc -o CMakeFiles/LogManager_test.dir/test_main.cc.s

# Object files for target LogManager_test
LogManager_test_OBJECTS = \
"CMakeFiles/LogManager_test.dir/test_main.cc.o"

# External object files for target LogManager_test
LogManager_test_EXTERNAL_OBJECTS =

test/LogManager_test: test/CMakeFiles/LogManager_test.dir/test_main.cc.o
test/LogManager_test: test/CMakeFiles/LogManager_test.dir/build.make
test/LogManager_test: /usr/local/lib/libdrogon.a
test/LogManager_test: /usr/local/lib/libtrantor.a
test/LogManager_test: /usr/lib/x86_64-linux-gnu/libjsoncpp.so
test/LogManager_test: /usr/lib/x86_64-linux-gnu/libuuid.so
test/LogManager_test: /usr/lib/x86_64-linux-gnu/libz.so
test/LogManager_test: /usr/local/lib/libssl.so
test/LogManager_test: /usr/local/lib/libcrypto.so
test/LogManager_test: test/CMakeFiles/LogManager_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/media/jojjiw/EX/ub-space/SGXAibeProject/client/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable LogManager_test"
	cd /media/jojjiw/EX/ub-space/SGXAibeProject/client/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/LogManager_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/LogManager_test.dir/build: test/LogManager_test

.PHONY : test/CMakeFiles/LogManager_test.dir/build

test/CMakeFiles/LogManager_test.dir/clean:
	cd /media/jojjiw/EX/ub-space/SGXAibeProject/client/test && $(CMAKE_COMMAND) -P CMakeFiles/LogManager_test.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/LogManager_test.dir/clean

test/CMakeFiles/LogManager_test.dir/depend:
	cd /media/jojjiw/EX/ub-space/SGXAibeProject/client && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /media/jojjiw/EX/ub-space/SGXAibeProject/client /media/jojjiw/EX/ub-space/SGXAibeProject/client/test /media/jojjiw/EX/ub-space/SGXAibeProject/client /media/jojjiw/EX/ub-space/SGXAibeProject/client/test /media/jojjiw/EX/ub-space/SGXAibeProject/client/test/CMakeFiles/LogManager_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/LogManager_test.dir/depend

