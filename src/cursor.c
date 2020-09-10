#include <stdio.h>
#include <stdint.h>
#include <capstone/capstone.h>
#include "binload.h"
#include "queue.h"

#define err_exit(err_msg, err_code)		\
{										\
	fprintf(stderr, err_msg "\n");		\
	err = err_code;						\
	goto exit;							\
}

void print_ins(cs_insn *ins);

int
main(int argc, char *argv[])
{
	csh cs_h;
	cs_insn *ins;
	int err;
	struct binary *bin;
	struct section *text_sec;
	uint8_t *pc;
	uint64_t addr;
	size_t size;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
		return 1;
	}

	err = 0;
	cs_h = 0;
	ins = NULL;

	bin = binary_load(argv[1]);
	if (!bin) {
		goto exit;
	}

	if (bin->type != BIN_TYPE_ELF || bin->arch != ARCH_X86) {
		err_exit("Unsupported binary type", 1);
	}

	text_sec = binary_get_section_by_name(bin, "text");
	if (!text_sec) {
		err_exit("Failed to get text section", 1);
	}

	if (cs_open(CS_ARCH_X86, bin->bits == 32 ? CS_MODE_32 : CS_MODE_64, &cs_h) != CS_ERR_OK) {
		err_exit("Capstone init failed", 1);
	}
	
	if (cs_option(cs_h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		err_exit("Capstone set option failed", 1);
	}

	ins = cs_malloc(cs_h);
	if (!ins) {
		err_exit("Capstone malloc failed", 1);
	}

	// TODO: Init queue for pushing addresses to disasm
	// TODO: Init linked list with addresses already seen

	while(cs_disasm_iter(cs_h, &pc, &size, &addr, ins)) {
	} 

exit:
	if (cs_h) cs_close(&cs_h);
	if (bin) binary_unload(bin);
	if (ins) cs_free(ins);

	return err;
}

void
print_ins(cs_insn *ins)
{
#define X86_INS_MAX_BYTES 15

	printf("0x%"PRIx64":\t", ins[i].address);
	for (j = 0; j < X86_INS_MAX_BYTES + 1; ++j) {
		if (j < ins[i].size) {
			printf("%02x ", ins[i].bytes[j]);
		} else {
			printf("   ");
		}
	}
	printf("\t%s", ins[i].mnemonic);
	printf("\t%s\n", ins[i].op_str);
}
