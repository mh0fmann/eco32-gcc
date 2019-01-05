/* Define default target values.  */

#undef MACHINE_TYPE
#define MACHINE_TYPE "NetBSD/eco32 ELF"

#undef  TARGET_OS_CPP_BUILTINS
#define TARGET_OS_CPP_BUILTINS()		\
  do						\
    {						\
      NETBSD_OS_CPP_BUILTINS_ELF();		\
      builtin_define ("__ECO32__");		\
      builtin_assert ("cpu=ECO32");		\
      builtin_assert ("machine=ECO32");	\
    }						\
  while (0)

#undef  CPP_SPEC
#define CPP_SPEC NETBSD_CPP_SPEC

#undef  STARTFILE_SPEC
#define STARTFILE_SPEC NETBSD_STARTFILE_SPEC

#undef  ENDFILE_SPEC
#define ENDFILE_SPEC NETBSD_ENDFILE_SPEC

#undef  LIB_SPEC
#define LIB_SPEC NETBSD_LIB_SPEC

#undef  TARGET_VERSION
#define TARGET_VERSION fprintf (stderr, " (NetBSD/ECO32 ELF)");

/* Make gcc agree with <machine/ansi.h> */

#undef WCHAR_TYPE
#define WCHAR_TYPE "int"

#undef WCHAR_TYPE_SIZE
#define WCHAR_TYPE_SIZE 32

#undef WINT_TYPE
#define WINT_TYPE "int"

/* Clean up after the generic ECO32/ELF configuration.  */
#undef MD_EXEC_PREFIX
#undef MD_STARTFILE_PREFIX

