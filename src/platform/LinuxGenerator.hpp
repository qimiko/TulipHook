#pragma once

#include "../Generator.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_LINUX)

namespace tulip::hook {

	class LinuxHandlerGenerator : public HandlerGenerator {
	public:
		using HandlerGenerator::HandlerGenerator;

		Result<> generateHandler() override;
		Result<std::vector<uint8_t>> generateIntervener() override;
		Result<> generateTrampoline(RelocateReturn offsets) override;
		Result<RelocateReturn> relocateOriginal(uint64_t target) override;

		std::string handlerString() override;
		std::string intervenerString() override;
		std::string trampolineString(size_t offset) override;

		void relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) override;
	};

	using PlatformHandlerGenerator = LinuxHandlerGenerator;

	class LinuxWrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;

		Result<void*> generateWrapper() override;
		Result<void*> generateReverseWrapper() override;

		std::string wrapperString() override;
		std::string reverseWrapperString() override;
	};

	using PlatformWrapperGenerator = LinuxWrapperGenerator;
}

#endif
