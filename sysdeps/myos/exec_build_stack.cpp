#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mlibc/all-sysdeps.hpp>

#include "config.h"
#include "utils.hpp"

static constexpr uint64_t AT_NULL = 0;
static constexpr uint64_t AT_PHDR = 3;
static constexpr uint64_t AT_PHENT = 4;
static constexpr uint64_t AT_PHNUM = 5;
static constexpr uint64_t AT_PAGESZ = 6;
static constexpr uint64_t AT_ENTRY = 9;
static constexpr uint64_t AT_RANDOM = 25;
static constexpr uint32_t ELF_MAGIC = 0x464C457Fu;
static constexpr uint16_t PT_PHDR = 6;

struct Elf64Ehdr {
	uint8_t e_ident[16];
	uint16_t e_type, e_machine;
	uint32_t e_version;
	uint64_t e_entry, e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize, e_phentsize, e_phnum;
	uint16_t e_shentsize, e_shnum, e_shstrndx;
};

struct Elf64Phdr {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset, p_vaddr, p_paddr;
	uint64_t p_filesz, p_memsz, p_align;
};

static void push_u64(unsigned char *&sp, uint64_t value) {
	*reinterpret_cast<uint64_t *>(sp) = value;
	sp += sizeof(uint64_t);
}

static int parse_elf_aux(const char * path, uintptr_t * at_entry, uintptr_t * at_phdr, uintptr_t * at_phent, uintptr_t * at_phnum) {
	int fd = -1;
	if (int e = mlibc::sysdep<Open>(path, O_RDONLY, 0, &fd)) {
		return e;
	}

	Elf64Ehdr ehdr{};
	ssize_t n = 0;
	if (int e = mlibc::sysdep<Read>(fd, &ehdr, sizeof(ehdr), &n)) {
		mlibc::sysdep<Close>(fd);
		return e;
	}
	if (n != static_cast<ssize_t>(sizeof(ehdr))) {
		mlibc::sysdep<Close>(fd);
		return ENOEXEC;
	}
	if (*reinterpret_cast<uint32_t *>(ehdr.e_ident) != ELF_MAGIC) {
		mlibc::sysdep<Close>(fd);
		return ENOEXEC;
	}

	*at_entry = ehdr.e_entry;
	*at_phent = ehdr.e_phentsize;
	*at_phnum = ehdr.e_phnum;
	*at_phdr = 0;
	for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
		Elf64Phdr phdr{};
		uint64_t off = ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize;
		off_t new_off = 0;
		if (int e = mlibc::sysdep<Seek>(fd, static_cast<off_t>(off), SEEK_SET, &new_off)) {
			(void)e;
			mlibc::sysdep<LibcLog>("failed in elf parse seek");
			mlibc::sysdep<LibcPanic>();
		}
		n = 0;
		if (int e = mlibc::sysdep<Read>(fd, &phdr, sizeof(phdr), &n)) {
			(void)e;
			mlibc::sysdep<LibcLog>("failed in elf parse read");
			mlibc::sysdep<LibcPanic>();
		}
		if (phdr.p_type != PT_PHDR)
			continue;
		*at_phdr = phdr.p_vaddr;
		mlibc::sysdep<Close>(fd);
		return 0;
	}
	mlibc::sysdep<Close>(fd);
	return ENOEXEC;
}

int build_exec_stack(const char * path, char * const argv[], char * const envp[], void ** stack_out, size_t * stack_size_out) {
	uintptr_t at_entry = 0;
	uintptr_t at_phdr = 0;
	uintptr_t at_phent = 0;
	uintptr_t at_phnum = 0;
	if (int e = parse_elf_aux(path, &at_entry, &at_phdr, &at_phent, &at_phnum)) {
		return e;
	}

	int argc = 0;
	int envc = 0;

	size_t total_stack_size = 0;
	total_stack_size += 16;

	while (argv[argc] != NULL) {
		total_stack_size += strlen(argv[argc]) + 1;
		argc += 1;
	}

	while (envp[envc] != NULL) {
		total_stack_size += strlen(envp[envc]) + 1;
		envc += 1;
	}

	size_t string_area_size = total_stack_size;

	// at this point we have the total size of all the strings that need to be stored
	// we need to round this to the nearest multiple of 8 for padding
	total_stack_size = align_up(total_stack_size, 8);

	total_stack_size += 7 * 16; // auxv entries: entry, phdr, phent, phnum, pagesz, random, null
	total_stack_size += sizeof(void *); // NULL terminator for envp
	total_stack_size += envc * sizeof(char *);
	total_stack_size += sizeof(void *); // NULL terminator for argv
	total_stack_size += argc * sizeof(char *);

	total_stack_size += 8; // argc is 8 bytes

	total_stack_size = align_up(total_stack_size, 16); // sp must be 16 byte aligned as per lp64 abi

	unsigned char * stack_pages_bot = static_cast<unsigned char *>(malloc(total_stack_size));
	if (stack_pages_bot == NULL)
		return ENOMEM;

	unsigned char * sp = stack_pages_bot;
	unsigned char * string_area = stack_pages_bot + total_stack_size - string_area_size;
	const uintptr_t stack_vma = static_cast<uintptr_t>(UMEM_STACK_BASE_VMA) - total_stack_size;
	auto vma_of = [&](const unsigned char *p) -> uint64_t {
		return static_cast<uint64_t>(stack_vma + static_cast<uintptr_t>(p - stack_pages_bot));
	};

	push_u64(sp, argc); // argc goes at the bottom

	memset(string_area, 0x67, 16); // AT_RANDOM 16 bytes
	unsigned char * at_random_ptr = string_area;
	string_area += 16;

	for (int i = 0; i < argc; ++i) {
		push_u64(sp, vma_of(string_area));
		size_t len = strlen(argv[i]) + 1;
		memcpy(string_area, argv[i], len);
		string_area += len;
	}

	push_u64(sp, 0);

	for (int i = 0; i < envc; ++i) {
		push_u64(sp, vma_of(string_area));
		size_t len = strlen(envp[i]) + 1;
		memcpy(string_area, envp[i], len);
		string_area += len;
	}

	push_u64(sp, 0);

	push_u64(sp, AT_ENTRY);
	push_u64(sp, at_entry);

	push_u64(sp, AT_PHDR);
	push_u64(sp, at_phdr);

	push_u64(sp, AT_PHENT);
	push_u64(sp, at_phent);

	push_u64(sp, AT_PHNUM);
	push_u64(sp, at_phnum);

	push_u64(sp, AT_PAGESZ);
	push_u64(sp, 4096);

	push_u64(sp, AT_RANDOM);
	push_u64(sp, vma_of(at_random_ptr));

	push_u64(sp, AT_NULL);
	push_u64(sp, 0);

	*stack_out = stack_pages_bot;
	*stack_size_out = total_stack_size;
	return 0;
}
