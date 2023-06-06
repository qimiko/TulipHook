#include "LinuxGenerator.hpp"

#include "../Handler.hpp"
#include "PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <sstream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_LINUX)

namespace {
	void* TULIP_HOOK_DEFAULT_CONV preHandler(HandlerContent* content) {
		Handler::incrementIndex(content);
		auto ret = Handler::getNextFunction(content);

		return ret;
	}

	void TULIP_HOOK_DEFAULT_CONV postHandler() {
		Handler::decrementIndex();
	}
}

std::string LinuxHandlerGenerator::handlerString() {
	// TODO: port macOS generator to x86
	return "";
}

std::string LinuxHandlerGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

std::string LinuxWrapperGenerator::wrapperString() {
	return "";
}

Result<void*> LinuxWrapperGenerator::generateWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

std::string LinuxWrapperGenerator::reverseWrapperString() {
	return "";
}

Result<void*> LinuxWrapperGenerator::generateReverseWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

#endif