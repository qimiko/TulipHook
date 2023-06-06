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
	return "";
}

std::string LinuxHandlerGenerator::trampolineString(size_t offset) {
	return "";
}

std::string LinuxWrapperGenerator::wrapperString() {
	return "";
}

Result<void*> LinuxWrapperGenerator::generateWrapper() {
	return Err("LinuxWrapperGenerator::generateWrapper unimplemented");
}

std::string LinuxWrapperGenerator::reverseWrapperString() {
	return "";
}

Result<void*> LinuxWrapperGenerator::generateReverseWrapper() {
	return Err("LinuxWrapperGenerator::generateReverseWrapper unimplemented");
}

#endif