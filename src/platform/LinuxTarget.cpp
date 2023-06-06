#include "LinuxTarget.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_LINUX)

#include <sys/mman.h>

Result<> LinuxTarget::allocatePage() {
	return Err("LinuxTarget::allocatePage unimplemented");
}

Result<uint32_t> LinuxTarget::getProtection(void* address) {
	return Err("LinuxTarget::getProtection unimplemented");
}

Result<> LinuxTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	return Err("LinuxTarget::protectMemory unimplemented");
}

Result<> LinuxTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	return Err("LinuxTarget::rawWriteMemory unimplemented");
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
