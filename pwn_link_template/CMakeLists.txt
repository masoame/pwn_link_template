# CMakeList.txt: pwn_link_template 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#

# 将源代码添加到此项目的可执行文件。

include_directories ("inc")
file (GLOB SOURCES_CPP "src/*.cpp")
file (GLOB SOURCES_C "inc/*.c")

add_executable (pwn_link_template ${SOURCES_C} ${SOURCES_CPP} "src/pwn_link_template.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET pwn_link_template PROPERTY CXX_STANDARD 23)
endif()

# TODO: 如有需要，请添加测试并安装目标。
