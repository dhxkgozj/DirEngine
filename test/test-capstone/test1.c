#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

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

    return 0;
}


