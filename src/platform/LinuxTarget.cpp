#include "LinuxTarget.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_LINUX)

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sys/mman.h>
#include <unistd.h>

namespace {
	// get the current page size
	// usually 4k, on some ARM platforms this may be increased to 16k
	inline long getPageSize() {
		return sysconf(_SC_PAGESIZE);
	}
}

Result<> LinuxTarget::allocatePage() {
	auto pageSize = getPageSize();
	m_allocatedPage = mmap(nullptr, pageSize, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (m_allocatedPage == MAP_FAILED) {
		return Err("Unable to allocate memory: " + std::to_string(errno));
	}

	m_currentOffset = 0;
	m_remainingOffset = pageSize;

	return Ok();
}

Result<uint32_t> LinuxTarget::getProtection(void* address) {
	std::ifstream f("/proc/self/maps");
	if (!f) {
		return Err("Failed to open process mappings");
	}

	std::string mapping;
	while (std::getline(f, mapping)) {
		// each line is of the format [start]-[end] [prot] ...
		// start and end are addresses in hex
		// prot is 4 characters, a fully allocated page will be rwxp
		std::uintptr_t start = 0;
		std::uintptr_t end = 0;
		char prot[4] = { 0 };

		std::sscanf(mapping.c_str(), "%x-%x %4c", &start, &end, &prot);

		// determine if address in range
		if (
			reinterpret_cast<std::uintptr_t>(address) >= start &&
			reinterpret_cast<std::uintptr_t>(address) < end
		) {
			auto ret = 0u;

			// last bit is if page is private, so no need to read
			if (prot[0] == 'r') {
				ret |= PROT_READ;
			}
			if (prot[1] == 'w') {
				ret |= PROT_WRITE;
			}
			if (prot[2] == 'x') {
				ret |= PROT_EXEC;
			}

			return Ok(ret);
		}
	}

	return Err("Unable to find address in mappings");
}

Result<> LinuxTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	// align address to page bounds (required for mprotect)
	auto pageSize = getPageSize();
	auto alignedAddress = reinterpret_cast<void*>(
		reinterpret_cast<std::uintptr_t>(address) & ~(pageSize - 1)
	);

	if (mprotect(alignedAddress, pageSize, protection) != 0) {
		return Err("Unable to protect memory: " + std::to_string(errno));
	}

	return Ok();
}

Result<> LinuxTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	// not sure if there's a case where the process being written to isn't our own
	// if this is necessary, rewrite this to use process_vm_writev, /proc/self/mem or ptrace
	std::memcpy(destination, source, size);
	return Ok();
}

uint32_t LinuxTarget::getMaxProtection() {
	return PROT_READ | PROT_WRITE | PROT_EXEC;
}

LinuxTarget& LinuxTarget::get() {
	static LinuxTarget ret;
	return ret;
}

// TODO: make arch chosen by Platform.hpp for compile time selection
Result<ks_engine*> LinuxTarget::openKeystone() {
	if (ks_open(KS_ARCH_X86, KS_MODE_32, &m_keystone) != KS_ERR_OK) {
		return Err("Couldn't open keystone");
	}
	if (ks_option(m_keystone, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM) != KS_ERR_OK) {
		return Err("Couldn't set keystone syntax to nasm");
	}

	return Ok(m_keystone);
}

Result<csh> LinuxTarget::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_32, &m_capstone);
	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}

#endif
