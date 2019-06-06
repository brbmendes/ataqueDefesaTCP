/* QNX Neutrino specific low level interface, for the remote server
   for GDB.
   Copyright (C) 2009-2019 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "server.h"
#include "nto-low.h"
#include "regdef.h"
#include "regcache.h"

#include <x86/context.h>
#include "common/x86-xstate.h"
#include "arch/i386.h"
#include "x86-tdesc.h"

const unsigned char x86_breakpoint[] = { 0xCC };
#define x86_breakpoint_len 1

/* Returns offset in appropriate Neutrino's context structure.
   Defined in x86/context.h.
   GDBREGNO is index into regs_i386 array.  It is autogenerated and
   hopefully doesn't change.  */
static int
nto_x86_register_offset (int gdbregno)
{
  if (gdbregno >= 0 && gdbregno < 16)
    {
      X86_CPU_REGISTERS *dummy = (void*)0;
      /* GPRs  */
      switch (gdbregno)
	{
	case 0: 
	  return (int)&(dummy->eax);
	case 1:
	  return (int)&(dummy->ecx);
	case 2:
	  return (int)&(dummy->edx);
	case 3:
	  return (int)&(dummy->ebx);
	case 4:
	  return (int)&(dummy->esp);
	case 5:
	  return (int)&(dummy->ebp);
	case 6:
	  return (int)&(dummy->esi);
	case 7:
	  return (int)&(dummy->edi);
	case 8:
	  return (int)&(dummy->eip);
	case 9:
	  return (int)&(dummy->efl);
	case 10:
	  return (int)&(dummy->cs);
	case 11:
	  return (int)&(dummy->ss);
#ifdef __SEGMENTS__
	case 12:
	  return (int)&(dummy->ds);
	case 13:
	  return (int)&(dummy->es);
	case 14:
	  return (int)&(dummy->fs);
	case 15:
	  return (int)&(dummy->gs);
#endif
	default:
	  return -1;
	}
    }
  return -1;
}

static void
nto_x86_arch_setup (void)
{
  the_low_target.num_regs = 16;
  struct target_desc *tdesc
    = i386_create_target_description (X86_XSTATE_SSE_MASK, false);

  init_target_desc (tdesc, i386_expedite_regs);

  nto_tdesc = tdesc;
}

struct nto_target_ops the_low_target =
{
  nto_x86_arch_setup,
  0, /* num_regs */
  nto_x86_register_offset,
  x86_breakpoint,
  x86_breakpoint_len
};



