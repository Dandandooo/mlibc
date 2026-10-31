#include <stddef.h>

#include "utils.hpp"

size_t align_up(size_t value, size_t alignment) {
	return (value + (alignment - 1)) & ~(alignment - 1);
}
