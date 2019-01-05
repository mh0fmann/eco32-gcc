/*
 * Target code for ECO32
 */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "rtl.h"
#include "regs.h"
#include "hard-reg-set.h"
#include "insn-config.h"
#include "conditions.h"
#include "insn-flags.h"
#include "output.h"
#include "insn-attr.h"
#include "flags.h"
#include "recog.h"
#include "reload.h"
#include "diagnostic-core.h"
#include "obstack.h"
#include "hash-set.h"
#include "machmode.h"
#include "vec.h"
#include "double-int.h"
#include "input.h"
#include "alias.h"
#include "symtab.h"
#include "wide-int.h"
#include "inchash.h"
#include "tree.h"
#include "stor-layout.h"
#include "varasm.h"
#include "calls.h"
#include "hashtab.h"
#include "function.h"
#include "statistics.h"
#include "real.h"
#include "fixed-value.h"
#include "expmed.h"
#include "dojump.h"
#include "explow.h"
#include "emit-rtl.h"
#include "stmt.h"
#include "expr.h"
#include "insn-codes.h"
#include "optabs.h"
#include "except.h"
#include "ggc.h"
#include "target.h"
#include "target-def.h"
#include "tm_p.h"
#include "langhooks.h"
#include "dominance.h"
#include "cfg.h"
#include "cfgrtl.h"
#include "cfganal.h"
#include "lcm.h"
#include "cfgbuild.h"
#include "cfgcleanup.h"
#include "predict.h"
#include "basic-block.h"
#include "df.h"
#include "builtins.h"

static int eco32_arg_partial_bytes (cumulative_args_t,
                                    enum machine_mode,
                                    tree,
                                    bool);
static bool eco32_pass_by_reference (cumulative_args_t,
                                     enum machine_mode,
                                     const_tree,
                                     bool);
static bool eco32_return_in_memory (const_tree, const_tree);
static bool eco32_frame_pointer_required (void);
static bool eco32_can_eliminate (int, int);
static bool eco32_must_pass_in_stack (enum machine_mode, const_tree);

static void eco32_setup_incoming_varargs (cumulative_args_t,
                                          enum machine_mode,
                                          tree,
                                          int *,
                                          int);

static void eco32_option_override (void);

static rtx eco32_function_arg (cumulative_args_t,
                               machine_mode,
                               const_tree,
                               bool);
static void eco32_function_arg_advance (cumulative_args_t,
                                        machine_mode,
                                        const_tree,
                                        bool);

static bool eco32_legitimate_constant_p (machine_mode, rtx);
static int eco32_return_pops_args (tree, tree, int);

static void eco32_asm_trampoline_template (FILE *);
static void eco32_trampoline_init (rtx, tree, rtx);

/* Initialize the GCC target structure.  */

#undef  TARGET_PROMOTE_PROTOTYPES
#define TARGET_PROMOTE_PROTOTYPES	hook_bool_const_tree_true

#undef  TARGET_RETURN_IN_MEMORY
#define TARGET_RETURN_IN_MEMORY		eco32_return_in_memory

#undef  TARGET_MUST_PASS_IN_STACK
#define TARGET_MUST_PASS_IN_STACK	eco32_must_pass_in_stack

#undef  TARGET_PASS_BY_REFERENCE
#define TARGET_PASS_BY_REFERENCE	eco32_pass_by_reference

#undef  TARGET_FRAME_POINTER_REQUIRED
#define TARGET_FRAME_POINTER_REQUIRED	eco32_frame_pointer_required

#undef  TARGET_CAN_ELIMINATE
#define TARGET_CAN_ELIMINATE		eco32_can_eliminate

#undef  TARGET_SETUP_INCOMING_VARARGS
#define TARGET_SETUP_INCOMING_VARARGS	eco32_setup_incoming_varargs

#undef  TARGET_ARG_PARTIAL_BYTES
#define TARGET_ARG_PARTIAL_BYTES	eco32_arg_partial_bytes

#undef  TARGET_OPTION_OVERRIDE
#define TARGET_OPTION_OVERRIDE		eco32_option_override

#undef  TARGET_FUNCTION_ARG
#define TARGET_FUNCTION_ARG		eco32_function_arg

#undef  TARGET_FUNCTION_ARG_ADVANCE
#define TARGET_FUNCTION_ARG_ADVANCE	eco32_function_arg_advance

#undef  TARGET_LEGITIMATE_CONSTANT_P
#define TARGET_LEGITIMATE_CONSTANT_P	eco32_legitimate_constant_p

#undef  TARGET_RETURN_POPS_ARGS
#define TARGET_RETURN_POPS_ARGS		eco32_return_pops_args

#undef  TARGET_ASM_TRAMPOLINE_TEMPLATE
#define TARGET_ASM_TRAMPOLINE_TEMPLATE	eco32_asm_trampoline_template

#undef  TARGET_TRAMPOLINE_INIT
#define TARGET_TRAMPOLINE_INIT		eco32_trampoline_init

#undef  TARGET_EXCEPT_UNWIND_INFO
#define TARGET_EXCEPT_UNWIND_INFO    sjlj_except_unwind_info

struct gcc_target targetm = TARGET_INITIALIZER;

/*#include "gt-eco32.h"*/

enum reg_class
eco32_reg_class(int);

#define LOSE_AND_RETURN(msgid, x)	\
  do {					\
    eco32_operand_lossage (msgid, x);	\
    return;				\
  } while (0)

/* Per-function machine data.  */
struct GTY(()) machine_function
{
  /* number of pretended arguments for varargs */
  int pretend_size;

  /* number of bytes saved on the stack for local variables */
  int local_vars_size;

  /* number of bytes saved on stack for register save area */
  int saved_reg_size;
  int save_ret;

  int sp_fp_offset;
  bool fp_needed;
  int size_for_adjusting_sp;

};

/* Allocate a chunk of memory for per-function machine-dependent data.  */

static struct machine_function *
eco32_init_machine_status (void)
{
  return ggc_cleared_alloc<machine_function> ();
}

static void
eco32_option_override (void)
{
  init_machine_status = eco32_init_machine_status;
}

static rtx
eco32_function_arg (cumulative_args_t ca,
                    machine_mode mode,
                    const_tree type,
                    bool named)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (ca);
  if (!named) {
    return NULL_RTX;
  }
  if (targetm.calls.must_pass_in_stack (mode, type)) {
    return NULL_RTX;
  }
  if (*cum > ECO32_LAST_ARG_REGNO) {
    return NULL_RTX;
  }
  return gen_rtx_REG (mode, *cum);
}

static void
eco32_function_arg_advance (cumulative_args_t ca,
                            machine_mode mode,
                            const_tree type,
                            bool named ATTRIBUTE_UNUSED)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (ca);
  *cum += eco32_num_arg_regs (mode, type);
}

static bool
eco32_legitimate_constant_p (machine_mode mode ATTRIBUTE_UNUSED,
                             rtx x ATTRIBUTE_UNUSED)
{
  return true;
}

static int
eco32_return_pops_args (tree fundecl ATTRIBUTE_UNUSED,
                        tree funtype ATTRIBUTE_UNUSED,
                        int size ATTRIBUTE_UNUSED)
{
  return 0;
}

enum reg_class
eco32_reg_class(int regno)
{
  if (is_ECO32_GENERAL_REG(regno))
  {
    return GENERAL_REGS;
  }
  if (is_ECO32_REG(regno))
  {
    return ALL_REGS;
  }
  return NO_REGS;
}

/* Worker function for TARGET_RETURN_IN_MEMORY.  */

static bool
eco32_return_in_memory (const_tree type,
                        const_tree fntype ATTRIBUTE_UNUSED)
{
  const HOST_WIDE_INT size = int_size_in_bytes (type);
  return (size == -1 || size > UNITS_PER_WORD);
}

/* Emit an error message when we're in an asm, and a fatal error for
"normal" insns.  Formatted output isn't easily implemented, since we
use output_operand_lossage to output the actual message and handle the
categorization of the error.  */

static void
eco32_operand_lossage(const char *msgid, rtx op)
{
  debug_rtx(op);
  output_operand_lossage("%s", msgid);
}

/* The PRINT_OPERAND_ADDRESS worker.  */

void
eco32_print_operand_address(FILE *file, rtx x)
{
  switch (GET_CODE(x))
  {
    case REG:
      fprintf(file, "%s,0", reg_names[REGNO(x)]);
    break;

    case PLUS:
      switch (GET_CODE(XEXP(x, 1)))
      {
        case CONST_INT:
          fprintf(file, "%s,%ld",
          reg_names[REGNO(XEXP(x, 0))],
          INTVAL(XEXP(x, 1)));
        break;
        case SYMBOL_REF:
          fprintf(file, "%s,",
          reg_names[REGNO(XEXP(x, 0))]);
          output_addr_const(file, XEXP(x, 1));
        break;
        case CONST:
        {
          rtx plus = XEXP(XEXP(x, 1), 0);
          if (GET_CODE(XEXP(plus, 0)) == SYMBOL_REF
          && CONST_INT_P(XEXP(plus, 1)))
          {
          fprintf (file, "%s,", reg_names[REGNO (XEXP (x, 0))]);
          output_addr_const (file, plus);
          }
          else
          abort();
        }
      break;
      default:
        abort();
      }
    break;

    default:
      output_addr_const(file, x);
    break;
  }
}

/* The PRINT_OPERAND worker.  */

void
eco32_print_operand(FILE *file, rtx x, int code)
{
  rtx operand = x;

  /* New code entries should just be added to the switch below.  If
  handling is finished, just return.  If handling was just a
  modification of the operand, the modified operand should be put in
  "operand", and then do a break to let default handling
  (zero-modifier) output the operand.  */
  switch (code)
  {
    case 'L':
      /* Print low (least significant) part of something. */
      switch (GET_CODE(operand))
      {
        case REG:
          /* Print reg + 1. */
          fprintf(file, "%s", reg_names[REGNO(operand) + 1]);
          return;

        default:
          LOSE_AND_RETURN("invalid operand for 'L' modifier", x);
      }
      break;

    case 0:
      /* No code, print as usual.  */
      break;

    default:
      LOSE_AND_RETURN("invalid operand modifier letter", x);
  }

  /* Print an operand as without a modifier letter.  */
  switch (GET_CODE(operand))
  {
  case REG:
    if (REGNO(operand) >= FIRST_PSEUDO_REGISTER)
    internal_error("internal error: bad register: %d",REGNO(operand));
    fprintf(file, "%s",reg_names[REGNO(operand)]);
    return;

  case MEM:
    PRINT_OPERAND_ADDRESS(file,XEXP(operand, 0));
  return;

  default:
    /* No need to handle all strange variants, let output_addr_const
    do it for us.  */
    if (CONSTANT_P(operand))
    {
      output_addr_const(file, operand);
      return;
    }
    LOSE_AND_RETURN("unexpected operand", x);
  }
}

/* Compute the size of the local area and the size
   to be adjusted by the prologue and epilogue.  */

static void
eco32_compute_frame(void)
{

  int regno;
  int args_size;


  args_size=(ACCUMULATE_OUTGOING_ARGS ? crtl->outgoing_args_size : 0);

  if(crtl->args.pretend_args_size > 0)
  {
    /*
    args_size+=crtl->args.pretend_args_size; 
    printf("%s pretend_args_size : %d \n",
           current_function_name(),
           crtl->args.pretend_args_size);
    */
    cfun->machine->pretend_size = crtl->args.pretend_args_size;
  }

  cfun->machine->fp_needed = FALSE;

  if(eco32_frame_pointer_required())
    cfun->machine->fp_needed = TRUE;

  cfun->machine->local_vars_size = get_frame_size();

  cfun->machine->saved_reg_size = 0;

  /* Save callee-saved registers.  */
  for (regno = 0; regno < FIRST_PSEUDO_REGISTER; regno++)
  {
    if (df_regs_ever_live_p(regno) && (!call_used_regs[regno]))
      cfun->machine->saved_reg_size += ECO32_REG_BYTE_SIZE;
  }

  if (!crtl->is_leaf)
    cfun->machine->save_ret = 1;

  cfun->machine->sp_fp_offset = args_size
                                + cfun->machine->saved_reg_size
                                + (cfun->machine->save_ret ?
                                    ECO32_REG_BYTE_SIZE : 0);

  cfun->machine->size_for_adjusting_sp = cfun->machine->local_vars_size
                                         + cfun->machine->saved_reg_size
                                         + (cfun->machine->save_ret ?
                                             ECO32_REG_BYTE_SIZE : 0)
                                         + args_size;
}

void
eco32_expand_prologue(void)
{
  int regno, temp = 0;
  rtx insn, reg, slot;

  eco32_compute_frame();

  if ( cfun->machine->pretend_size > 0)
  {
    /* varargs present */
    for (regno = ECO32_FIRST_ARG_REGNO; regno <= ECO32_LAST_ARG_REGNO; regno++)
    {
      reg = gen_rtx_REG(SImode, regno);
      slot = gen_rtx_PLUS(SImode, stack_pointer_rtx, GEN_INT(temp));
      insn = gen_movsi( gen_rtx_MEM(SImode, slot), reg);
      insn = emit(insn);
      RTX_FRAME_RELATED_P(insn) = 1;
      temp += 4;
    }
  }  

  /* adjust sp size */
  if (cfun->machine->size_for_adjusting_sp > 0)
  {
    insn =
      emit_insn(gen_subsi3(stack_pointer_rtx,
                           stack_pointer_rtx,
                           GEN_INT(cfun->machine->size_for_adjusting_sp)));
    RTX_FRAME_RELATED_P(insn) = 1;
  }

  /* skip outgoing args*/
  temp = (ACCUMULATE_OUTGOING_ARGS ? crtl->outgoing_args_size : 0);

  /* save callee-saved registers */
  for (regno = 0; regno < FIRST_PSEUDO_REGISTER; regno++)
  {
    if (!fixed_regs[regno] &&
        df_regs_ever_live_p(regno) &&
        !call_used_regs[regno])
    {
      reg = gen_rtx_REG(SImode, regno);
      slot = gen_rtx_PLUS(SImode, stack_pointer_rtx, GEN_INT(temp));
      insn = gen_movsi( gen_rtx_MEM(SImode, slot), reg);
      insn = emit(insn);
      RTX_FRAME_RELATED_P(insn) = 1;
      temp += 4;
    }
  }

  if (cfun->machine->save_ret)
  {
    reg = gen_rtx_REG(SImode, RETURN_ADDRESS_REGNUM);
    slot = gen_rtx_PLUS(SImode, stack_pointer_rtx, GEN_INT(temp));
    insn = gen_movsi(gen_rtx_MEM(SImode, slot),reg);
    insn = emit(insn);
    RTX_FRAME_RELATED_P(insn) = 1;
    temp += 4;
  }

  /* set fp to sp + sp_fp_offset */
  temp = cfun->machine->sp_fp_offset;
  insn = gen_addsi3(frame_pointer_rtx,stack_pointer_rtx,GEN_INT(temp));
  insn = emit(insn);
  RTX_FRAME_RELATED_P(insn) = 1;
}

void
eco32_expand_epilogue(void)
{
  int regno, temp=0;
  rtx reg, insn, slot;
  temp = cfun->machine->size_for_adjusting_sp -
         cfun->machine->local_vars_size;

  if (cfun->machine->save_ret)
  {
    temp -= 4;
    reg = gen_rtx_REG(SImode, RETURN_ADDRESS_REGNUM);
    slot = gen_rtx_PLUS(SImode, stack_pointer_rtx, GEN_INT(temp));
    insn = gen_movsi(reg, gen_rtx_MEM(SImode, slot));
    insn = emit(insn);
  }

  if (cfun->machine->saved_reg_size != 0)
  {
    for (regno = FIRST_PSEUDO_REGISTER;regno-- > 0;)
    {
      if (!fixed_regs[regno] &&
          !call_used_regs[regno] &&
          df_regs_ever_live_p(regno))
      {
        temp -= 4;
        reg = gen_rtx_REG(SImode, regno);
        slot = gen_rtx_PLUS(SImode, stack_pointer_rtx, GEN_INT(temp));
        insn = gen_movsi(reg,
        gen_rtx_MEM(SImode, slot));
        insn = emit(insn);
      }
    }
  }

  if (cfun->machine->size_for_adjusting_sp > 0)
  {
    insn =
      emit_insn(gen_addsi3(stack_pointer_rtx,
                           stack_pointer_rtx,
                           GEN_INT(cfun->machine->size_for_adjusting_sp)));
  }

  emit_jump_insn (gen_returner());
}

/* Implement RETURN_ADDR_RTX (COUNT, FRAMEADDR).
   We currently only support calculating the return address
   for the current frame. */
rtx
eco32_return_addr_rtx (int count, rtx frame ATTRIBUTE_UNUSED)
{
  if (count)
    return NULL_RTX;

  eco32_compute_frame ();

  /* saved return addr for current function is at fp - 4 */
  if (cfun->machine->save_ret)
    return gen_rtx_MEM (Pmode,
                        plus_constant (Pmode,
                                       frame_pointer_rtx,
                                       -UNITS_PER_WORD));

  return get_hard_reg_initial_val (Pmode, RETURN_ADDRESS_REGNUM);
}

/* Implements the macro INITIAL_ELIMINATION_OFFSET,
   return the OFFSET.  */
int
eco32_initial_elimination_offset(int from, int to)
{
  int ret = 0;
  eco32_compute_frame();

  if ((from) == FRAME_POINTER_REGNUM && (to) == STACK_POINTER_REGNUM)
  {
    ret = cfun->machine->sp_fp_offset;
  }
  else if ((from) == ARG_POINTER_REGNUM && (to) == FRAME_POINTER_REGNUM)
  {
    ret = cfun->machine->local_vars_size;
  }
  else
  {
    abort();
  }

  return ret;
}


/* Return non-zero if the function argument described by TYPE
   is to be passed by reference.  */
static bool
eco32_pass_by_reference (cumulative_args_t cum_v ATTRIBUTE_UNUSED,
                         enum machine_mode mode,
                         const_tree type,
                         bool named ATTRIBUTE_UNUSED)
{
  unsigned HOST_WIDE_INT size;

  if (type)
  {
    if (AGGREGATE_TYPE_P(type))
    {
      return TRUE;
    }
    size = int_size_in_bytes (type);
  }
  else
    size = GET_MODE_SIZE (mode);

  return size > GET_MODE_SIZE(SImode) ;
  /* > 4byte : is this okay?
     The idea is to pass everything larger than an int
     by reference (or on stack) */
}

bool
eco32_frame_pointer_required(void)
{
  return true;
}

static bool
eco32_can_eliminate(int from ATTRIBUTE_UNUSED, int to ATTRIBUTE_UNUSED)
{
  return true;
}

static bool
eco32_must_pass_in_stack (enum machine_mode mode, const_tree type)
{
  if ( mode == BLKmode)
  {
    return true;
  }

  if (type == NULL)
  {
    return false;
  }

  return AGGREGATE_TYPE_P(type);
}


/* Compute the number of word sized registers needed to hold a
   function argument of mode INT_MODE and tree type TYPE.  */
int
eco32_num_arg_regs (enum machine_mode mode, const_tree type)
{
  int size;

  if (targetm.calls.must_pass_in_stack (mode, type))
    return 0;

  if (type && mode == BLKmode)
    size = int_size_in_bytes (type);
  else
    size = GET_MODE_SIZE (mode);

  return size > 0 ? (size + UNITS_PER_WORD - 1) / UNITS_PER_WORD : 0;
}

/* varargs pushed in function prologue */
void
eco32_setup_incoming_varargs (cumulative_args_t cum_v,
                              enum machine_mode mode,
                              tree type,
                              int *pretend_size,
                              int no_rtl)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);
  int size = ECO32_FIRST_ARG_REGNO + ECO32_NUM_ARG_REGS - *cum;
  int offset = (*cum - ECO32_FIRST_ARG_REGNO) * UNITS_PER_WORD;

  *pretend_size = size * UNITS_PER_WORD;

  if (no_rtl)
    return;

  gcc_assert (mode != BLKmode);
/*
  if (*cum < (ECO32_LAST_ARG_REGNO+1))
  {
    
    rtx regblock = gen_rtx_MEM (BLKmode,
                     plus_constant (Pmode,
                       arg_pointer_rtx,
                       offset));
    move_block_from_reg (*cum, regblock, size);
  }
*/  
}

static int
eco32_arg_partial_bytes (cumulative_args_t cum_v,
                         enum machine_mode mode,
                         tree type,
                         bool named ATTRIBUTE_UNUSED)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);
  int words;
  unsigned int regs = eco32_num_arg_regs (mode, type);

  if (*cum >= ECO32_LAST_ARG_REGNO+1)
    words = 0;
  else if ((*cum + regs) > ECO32_LAST_ARG_REGNO+1)
    words = (*cum + regs) - ECO32_LAST_ARG_REGNO+1;
  else
    words = 0;

  return words * UNITS_PER_WORD;
}

/* totally buggy - we can't return pointers to nested functions */

static void
eco32_asm_trampoline_template (FILE *f)
{
  fprintf(f, "\tldhi $1,0\n");
  fprintf(f, "\tori $1,$1,0\n");
  fprintf(f, "\tadd $3,$0,$1\n");

  fprintf(f, "\tldhi $1,0\n");
  fprintf(f, "\tori $1,$1,0\n");
  fprintf (f, "\tjr  $1\n");
}

/* Worker function for TARGET_TRAMPOLINE_INIT.  */
static void
eco32_trampoline_init (rtx m_tramp, tree fndecl, rtx chain_value)
{
  rtx mem , fnaddr = XEXP (DECL_RTL (fndecl), 0);
  /* get addr of target function */

  /* load template on stack - this could be avoided I guess*/
  emit_block_move (m_tramp, assemble_trampoline_template (),
    GEN_INT (TRAMPOLINE_SIZE), BLOCK_OP_NORMAL);

  /* COMPILER CAN'T USE $1 for anything */
  /*
  we exploit $3 (SCP-Reg) for computation
  this is totally save since the trampoline puts the right value into $3
  $3 (SCP) can't be set here because the value may get lost over the course
  of the runnig program, therefore the modified template has to set $3 (SCP)
  to the right value

  That is at runtime:
  Load template on stack of function that nests another function
  modify template on stack
  load value into $3
  store fnaddr into template
  continue normal execution...
  template gets called and fn is called
  */

  emit_move_insn (gen_rtx_REG(SImode, eco32_SCP), chain_value);
  /* slri $3,$3,16 */
  emit_insn(
    gen_lshrsi3(
      gen_rtx_REG(SImode, eco32_SCP),
      gen_rtx_REG(SImode, eco32_SCP),
      GEN_INT(16)
    )
  );
  /* encode into template */
  mem = adjust_address (m_tramp, HImode, 2);
  emit_move_insn(mem,gen_rtx_REG(HImode,eco32_SCP));


  /* store fnaddr in $3 */
  emit_move_insn (gen_rtx_REG(SImode, eco32_SCP), chain_value);
  /* andi $3,$3,0x0FF */
  emit_insn(
    gen_andsi3(
      gen_rtx_REG(SImode, eco32_SCP),
      gen_rtx_REG(SImode, eco32_SCP),
      GEN_INT(0xFFFF)
    )
  );

  /* encode into template */
  mem = adjust_address (m_tramp, HImode, 6);
  emit_move_insn(mem,gen_rtx_REG(HImode,eco32_SCP));


  /* store fnaddr in $3 */
  emit_move_insn (gen_rtx_REG(SImode, eco32_SCP), fnaddr);
  /* linker puts the right addr here */
  /* slri $3,$3,16 */
  emit_insn(
    gen_lshrsi3(
      gen_rtx_REG(SImode, eco32_SCP),
      gen_rtx_REG(SImode, eco32_SCP),
      GEN_INT(16)
    )
  );
  /* encode into template */
  mem = adjust_address (m_tramp, HImode, 14);
  emit_move_insn(mem,gen_rtx_REG(HImode,eco32_SCP));


  /* store fnaddr in $3 */
  emit_move_insn (gen_rtx_REG(SImode, eco32_SCP), fnaddr);
  /* andi $3,$3,0x0FF */
  emit_insn(
    gen_andsi3(
      gen_rtx_REG(SImode, eco32_SCP),
      gen_rtx_REG(SImode, eco32_SCP),
      GEN_INT(0xFFFF)
    )
  );

  /* encode into template */
  mem = adjust_address (m_tramp, HImode, 18);
  emit_move_insn(mem,gen_rtx_REG(HImode,eco32_SCP));

}

#include "gt-eco32.h"
