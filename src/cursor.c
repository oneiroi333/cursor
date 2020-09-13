#include <stdio.h>
#include <stdint.h>
#include <capstone/capstone.h>
#include "binload.h"
#include "queue.h"

#define err_exit(err_msg)			\
{									\
	fprintf(stderr, err_msg "\n");	\
	err = 1;						\
	goto exit;						\
}

struct _ctx {
	struct binary *bin;
	struct queue *queue;
};

static void print_ins(cs_insn *ins);
static void *enqueue_addr_to_disasm(void *addrs_to_disasm, void *data);
static void *search_addrs_seen(void *addr, void *data);
static int is_cflow_group(uint8_t group);
static int is_cflow_ins(cs_insn *ins);
static int is_unconditional_cflow_ins(cs_insn *ins);
static uint64_t get_ins_immediate_target(cs_insn *ins);

int
main(int argc, char *argv[])
{
	csh cs_h;
	cs_insn *ins;
	int err;
	const uint8_t *pc;
	uint64_t addr, offset, target;
	size_t size;
	struct binary *bin;
	struct section *text_sec;
	struct queue *addrs_to_disasm;
	struct llist *addrs_seen;

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
		err_exit("Unsupported binary type");
	}

	text_sec = binary_get_section_by_name(bin, "text");
	if (!text_sec) {
		err_exit("Failed to get text section");
	}

	if (cs_open(CS_ARCH_X86, bin->bits == 32 ? CS_MODE_32 : CS_MODE_64, &cs_h) != CS_ERR_OK) {
		err_exit("Capstone init failed");
	}
	
	if (cs_option(cs_h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		err_exit("Capstone set option failed");
	}

	ins = cs_malloc(cs_h);
	if (!ins) {
		err_exit("Capstone malloc failed");
	}

	/* Create queue */
	addrs_to_disasm = queue_init(0);
	/* Add binary entry address */
	queue_enqueue(addrs_to_disasm, (void *)bin->entry);
	/* Add all symbol addresses */
	struct _ctx ctx = {
		.bin = bin,
		.queue = addrs_to_disasm
	};
	llist_traverse(bin->symbols, (void *)&ctx, enqueue_addr_to_disasm);

	/* Start disassembling */
	addrs_seen = NULL;
	while(!queue_empty(addrs_to_disasm)) {
		addr = (uint64_t)queue_dequeue(addrs_to_disasm);
		/* Skip already disasm addr */
		if (llist_search(addrs_seen, (void *)addr, search_addrs_seen, NULL)) {
			continue;
		}
		/* Add addr to already disassembled adresses */
		if (addrs_seen == NULL) {
			addrs_seen = llist_init((void *)addr);
		} else {
			llist_append(addrs_seen, (void *)addr);
		}

		offset = addr - text_sec->vma;
		pc = text_sec->bytes + offset;
		size = text_sec->size - offset;
		while(cs_disasm_iter(cs_h, &pc, &size, &addr, ins)) {
			if (ins->id == X86_INS_INVALID || ins->size == 0) {
				break;
			}
			print_ins(ins);
			/* Check/handle control flow instruction */
			if (is_cflow_ins(ins)) {
				target = get_ins_immediate_target(ins);
				/* If the target is legit and not processed yet, add it to the queue */
				if (target &&
					binary_sec_contains_addr(text_sec, target) &&
					!llist_search(addrs_seen, (void *)target, search_addrs_seen, NULL)) {
						queue_enqueue(addrs_to_disasm, (void *)target);
				}
				if (is_unconditional_cflow_ins(ins)) {
					break;
				}
			} else {
				if (ins->id == X86_INS_HLT) {
					break;
				}
			}
		} 
		printf("---------------------------------------------\n");
	}
	queue_destroy(addrs_to_disasm, NULL, NULL);

exit:
	if (cs_h) cs_close(&cs_h);
	if (bin) binary_unload(bin);
	if (ins) cs_free(ins, 1);

	return err;
}

static void *
enqueue_addr_to_disasm(void *ctx, void *symbol)
{
	struct binary *bin;
	struct queue *queue;
	struct symbol *sym;
	struct section *sec;

	/* Parse context */
	bin = (struct binary *)((struct _ctx *)ctx)->bin;
	queue = (struct queue *)((struct _ctx *)ctx)->queue;

	sym = (struct symbol *)symbol;
	sec = binary_get_section_by_name(bin, "text");

	if (sym->type == SYM_TYPE_FUNC && sec && binary_sec_contains_addr(sec, sym->addr)) {
		queue_enqueue(queue, (void *)sym->addr);
	}
	return NULL;
}

static void *
search_addrs_seen(void *addr, void *data)
{
	return ((uint64_t)addr == (uint64_t)data ? (void *)1 : (void *)0);
}

static void
print_ins(cs_insn *ins)
{
#define X86_INS_MAX_BYTES 15

	size_t i, j;

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

static int
is_cflow_group(uint8_t grp)
{
	return (grp == CS_GRP_JUMP) || (grp == CS_GRP_CALL)
			|| (grp == CS_GRP_RET) || (grp == CS_GRP_IRET);
}

static int
is_cflow_ins(cs_insn *ins)
{
	for (int i = 0; i < ins->detail->groups_count; ++i) {
		if (is_cflow_group(ins->detail->groups[i])) {
			return 1;
		}
	}
	return 0;
}

static int
is_unconditional_cflow_ins(cs_insn *ins)
{
	switch(ins->id) {
	case X86_INS_JMP:
	case X86_INS_LJMP:
	case X86_INS_RET:
	case X86_INS_RETF:
	case X86_INS_RETFQ:
		return 1;
	default:
		return 0;
	}
}

static uint64_t
get_ins_immediate_target(cs_insn *ins)
{
	cs_x86_op *cs_op;

	for (size_t i = 0; i < ins->detail->groups_count; ++i) {
		if (is_cflow_group(ins->detail->groups[i])) {
			for (size_t j = 0; j < ins->detail->x86.op_count; ++j) {
				cs_op = &ins->detail->x86.operands[j];
				if (cs_op->type == X86_OP_IMM) {
					return cs_op->imm;
				}
			}
		}
	}
	return 0;
}
