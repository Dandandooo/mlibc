#include <stddef.h>

int build_exec_stack(const char * path, char * const argv[], char * const envp[], void ** stack_out, size_t * stack_size_out);
