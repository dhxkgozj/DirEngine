#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <capstone/capstone.h>
#include "libvex_basictypes.h"
#include "libvex.h"
#include "test1.h"

#define CODE "\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c"
__attribute__ ((noreturn))
static
void failure_exit ( void )
{
   fprintf(stdout, "VEX did failure_exit.  Bye.\n");
   exit(1);
}

static
void log_bytes ( const HChar* bytes, SizeT nbytes )
{
   fwrite ( bytes, 1, nbytes, stdout );
}

static Bool chase_into_not_ok ( void* opaque, Addr dst ) {
   return False;
}
static UInt needs_self_check ( void *closureV, VexRegisterUpdates *pxControl,
                               const VexGuestExtents *vge ) {
   return 0;
}
int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}

	count = cs_disasm(handle, (unsigned char *)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
	if (count) {
		size_t j;

		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
	// Capstone ---------------------------------------------------------------------------------

   	VexTranslateResult tres;
	VexTranslateArgs vta;
	VexControl vcon;
	VexArchInfo vai_amd64;
	VexAbiInfo vbi;
	VexGuestExtents vge;

	LibVEX_default_VexControl ( &vcon );
	vcon.iropt_level = 2;
	vcon.guest_max_insns = 60;

   	LibVEX_Init ( &failure_exit, &log_bytes, 
	1,  /* debug_paranoia */ 
	&vcon );
	LibVEX_default_VexArchInfo(&vai_amd64);
	vai_amd64.hwcaps = 0;
	vai_amd64.endness = VexEndnessLE;
	LibVEX_default_VexAbiInfo(&vbi);
	vbi.guest_stack_redzone_size = 128;

	vta.abiinfo_both    = vbi;
	vta.guest_bytes     = (unsigned char *)CODE;
	vta.guest_bytes_addr = 0x1000;
	vta.callback_opaque = NULL;
	vta.chase_into_ok   = chase_into_not_ok;
	vta.guest_extents   = &vge;
	vta.host_bytes      = NULL;
	vta.host_bytes_size = 0;
	vta.host_bytes_used = NULL;
	vta.arch_guest     = VexArchAMD64;
	vta.archinfo_guest = vai_amd64;
	vta.arch_host      = VexArchAMD64;
	vta.archinfo_host  = vai_amd64;
	vta.needs_self_check  = needs_self_check;
	vta.preamble_function = NULL;
	vta.traceflags      = VEX_TRACE_FE;
	vta.addProfInc      = False;
	vta.sigill_diag     = True;
	vta.instrument1     = NULL;
    vta.instrument2     = NULL;
	vta.disp_cp_chain_me_to_slowEP = (void*)0x12345678;
	vta.disp_cp_chain_me_to_fastEP = (void*)0x12345679;
	vta.disp_cp_xindir             = (void*)0x1234567A;
	vta.disp_cp_xassisted          = (void*)0x1234567B;
    vta.finaltidy = NULL;
    tres = LibVEX_Translate ( &vta );
	if (tres.status != VexTransOK)
		printf("hello world\n");
		printf("\ntres = %d\n", (Int)tres.status);

    return 0;
}


