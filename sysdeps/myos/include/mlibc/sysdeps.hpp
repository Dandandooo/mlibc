#pragma once

#include <mlibc/sysdep-signatures.hpp>

namespace mlibc {

struct MyosSysdepTags :
	LibcPanic,
	LibcLog,
	Isatty,
	Write,
	TcbSet,
	AnonAllocate,
	AnonFree,
	Seek,
	Exit,
	ThreadExit,
	Close,
	FutexWake,
	FutexWait,
	Read,
	Open,
	VmMap,
	VmUnmap,
	ClockGet,
	Sleep,
	Fork,
	Waitpid,
	Execve,
	PrepareStack,
	Clone,
	Pipe,
	Dup,
	Dup2
{};

template<typename Tag>
using Sysdeps = SysdepOf<MyosSysdepTags, Tag>;

struct SysdepTraits {
	static constexpr bool usesRtNetlink = false;
};

} // namespace mlibc
