#include "code_compiler.h"

#include <format>
#include <sstream>
#include <iostream>
#include <capstone/capstone.h>

extern csh handle;
extern std::string code_output;
extern std::string compiler_output;

std::map<uintptr_t, size_t> section_sizes{};

/*
	JIT Event Listener registered below to capture the size & address of the sections created. Without this,
	disassembling won't know when to stop.
*/
class Listener : public llvm::JITEventListener {
public:
	void notifyObjectLoaded(llvm::JITEventListener::ObjectKey Key, const llvm::object::ObjectFile &Obj,
							const llvm::RuntimeDyld::LoadedObjectInfo &L) override {
		section_sizes.clear();
		for (const auto& section : Obj.sections()) {
			auto size = section.getSize();
			if (size) {
				auto name = section.getName();
				auto address = L.getSectionLoadAddress(section);
				// Just like in a normal executable, it'll create the sections like .text etc.
				if (name && strcmp(name->data(), ".text") == 0)
					section_sizes[address] = size;
			}
		}
	}
};

bool generate_shellcode(std::string contents, std::vector<std::string> args) {
	compiler_output.clear();

	// Create all the diagnostic stuff required for the compiler
	clang::IntrusiveRefCntPtr<clang::DiagnosticOptions> diagOptions = new clang::DiagnosticOptions();

	// Wrapping our output into the raw_string_ostream so if execution fails, we have the output
	llvm::raw_string_ostream os(compiler_output);
	clang::TextDiagnosticPrinter* diagClient = new clang::TextDiagnosticPrinter(os, &*diagOptions);

	clang::IntrusiveRefCntPtr<clang::DiagnosticIDs> diagIDs(new clang::DiagnosticIDs());
	clang::DiagnosticsEngine diagEngine(diagIDs, &*diagOptions, diagClient);

	// Initialize the compiler instance and pass the arguments to it
	clang::CompilerInstance compilerInstance;
	auto& compilerInvocation = compilerInstance.getInvocation();
	compilerInstance.createDiagnostics(diagClient, false);

	std::vector<const char*> items;
	// Check if we're passing a triple already
	const auto contains_triple = std::any_of(args.begin(), args.end(), [](const auto& arg) { 
												return arg.find("-triple") != std::string::npos; });
	if (!contains_triple)
		args.insert(args.begin(), "-triple=" + llvm::sys::getProcessTriple());

	for (auto& arg : args) {
		// Per documents, should not contain cc1:
		// https://github.com/llvm/llvm-project/blob/0762b2e6cacf9a1aa8b5e832206f4c94744d0150/clang/include/clang/Frontend/CompilerInvocation.h#L208
		if (arg == "-cc1")
			continue;
		items.push_back(arg.c_str());
	}

	clang::CompilerInvocation::CreateFromArgs(compilerInvocation, llvm::ArrayRef(items.data(), items.size()), diagEngine);

	// TODO: Fix up header searching
	auto& headerSearchOptions = compilerInstance.getHeaderSearchOpts();
	headerSearchOptions.UseBuiltinIncludes = true;
	headerSearchOptions.UseStandardSystemIncludes = true;

	// Front end options contain all our files to compile
	auto& frontEndOptions = compilerInstance.getFrontendOpts();
	frontEndOptions.Inputs.clear();	
	auto buffer = llvm::MemoryBuffer::getMemBuffer(contents);
	frontEndOptions.Inputs.push_back(clang::FrontendInputFile(buffer->getMemBufferRef(), clang::InputKind(clang::Language::C)));

	// Target options to update the host compiler triple and target
	auto& targetOptions = compilerInstance.getTargetOpts();
	targetOptions.HostTriple = llvm::sys::getProcessTriple();
	if (!contains_triple)
		targetOptions.Triple = targetOptions.HostTriple;
	
	// Create the code generation action that will convert the code into LLVM IR
	llvm::LLVMContext context;
	std::unique_ptr<clang::CodeGenAction> action = std::make_unique<clang::EmitLLVMOnlyAction>(&context);
	if (!compilerInstance.ExecuteAction(*action))
		return false;

	auto unique_module = action->takeModule();
	auto module = unique_module.get();
	
	std::string errorMsg;
	std::unique_ptr<llvm::ExecutionEngine> executionEngine(llvm::EngineBuilder(std::move(unique_module))
		.setErrorStr(&errorMsg)
		.setEngineKind(llvm::EngineKind::JIT)
		.setVerifyModules(true)
		.setRelocationModel(llvm::Reloc::Static)
		// Prevents it from adding stuff like memset/memcpy otherwise should be Small
		.setCodeModel(llvm::CodeModel::Kernel)
		.setMCJITMemoryManager(std::make_unique<llvm::SectionMemoryManager>())
		.create());

	if (!executionEngine) {
		compiler_output = errorMsg;
		return false;
	}

	// Listener class to capture info about the compiled code
	Listener listener;
	executionEngine->RegisterJITEventListener(&listener);
	//executionEngine->DisableLazyCompilation(true);

	// Calling finalize object will compile everything now from IR to our MC
	executionEngine->finalizeObject();

	if (!executionEngine->hasError()) {
		auto& v = module->getValueSymbolTable();
		// First we're going to loop through to capture the function names, and their start
		std::unordered_map<uintptr_t, std::string> functions;
		for (auto& symbol : v) {
			auto func = executionEngine->getFunctionAddress(symbol.getKeyData());
			for (auto& [section, size] : section_sizes) {
				if (func >= section && func < section + size) {
					functions.insert( {func, symbol.getKeyData() } );
					break;
				}
			}
		}

		// There should only be 1 section (.text) but who knows. Just loop all
		for (auto& [section_address, section_size] : section_sizes) {
			auto insn = cs_malloc(handle);
			uintptr_t address = section_address;
			auto size = section_size;
			auto insn_addr = reinterpret_cast<const uint8_t*>(address);
			// First pass will give us the info for our padding in the output pane
			uint32_t longest_instruction = 0;
			uint32_t longest_mnemonic = 0;
			while (cs_disasm_iter(handle, &insn_addr, &size, &address, insn)) {
				if (insn->size > longest_instruction)
					longest_instruction = insn->size;
				auto len = strlen(insn->mnemonic);
				if (len > longest_mnemonic)
					longest_mnemonic = len;
			}
			// Reset the variables for the loop again which actually produces the output
			size = section_size;
			address = section_address;
			insn_addr = reinterpret_cast<const uint8_t*>(address);
			std::stringstream outsstr;
			uint32_t idx = 0;
			while (cs_disasm_iter(handle, &insn_addr, &size, &address, insn)) {
				if (functions.count(insn->address))
					outsstr << "// " << functions[insn->address] << std::endl;
				std::stringstream sstr;
				for (auto i = 0; i < insn->size; ++i) {
					if (size == 0) {
						if (i == insn->size - 1)
							sstr << std::format("0x{:02X}", insn->bytes[i]);
						else
							sstr << std::format("0x{:02X}, ", insn->bytes[i]);
					} else {
						sstr << std::format("0x{:02X}, ", insn->bytes[i]);
					}
				}
				outsstr << std::format("{:{}}//{:3x}: {:{}}\t", sstr.str(), longest_instruction * 6, idx, insn->mnemonic, longest_mnemonic);
				// Checking here if it's a call or jump to one of our created functions to replace the address with the name
				if ((cs_insn_group(handle, insn, CS_GRP_CALL) || cs_insn_group(handle, insn, CS_GRP_JUMP)) &&
						cs_op_count(handle, insn, CS_OP_IMM)) {
					auto target = X86_REL_ADDR(insn[0]);
					if (functions.count(target)) {
						outsstr << functions[target] << std::endl;
					} else {
						outsstr << "0x" << std::hex << (target - section_address) << std::endl;
					}
				} else {
					outsstr << insn->op_str << std::endl;
				}
				idx += insn->size;
			}
			code_output = outsstr.str();
			cs_free(insn, 1);
		}
	} else {
		compiler_output = executionEngine->getErrorMessage();
		return false;
	}
	return true;
}