/*
 * Target support for ECO32
 */

#undef  TARGET_OS_CPP_BUILTINS
#define TARGET_OS_CPP_BUILTINS()		\
  do						\
    {						\
      GNU_USER_TARGET_OS_CPP_BUILTINS();	\
    }						\
  while (0)

#undef CPP_SPEC
#define CPP_SPEC "%{posix:-D_POSIX_SOURCE} %{pthread:-D_REENTRANT}"

#define GLIBC_DYNAMIC_LINKER "/lib/ld.so.1"

#undef LINK_SPEC
#define LINK_SPEC \
 "%{shared:-shared} \
  %{!shared: \
    %{!static: \
      %{rdynamic:-export-dynamic} \
      -dynamic-linker " GNU_USER_DYNAMIC_LINKER "} \
    %{static:-static}}"
