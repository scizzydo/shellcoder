#pragma once
#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(disable: 4624)
#pragma warning(disable: 4141)
#pragma warning(disable: 4291)
#include <llvm/InitializePasses.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/JITEventListener.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/Registry.h>
#include <llvm/TargetParser/Host.h>
#include <llvm/IR/ValueSymbolTable.h>

#include <clang/Basic/DiagnosticOptions.h>
#include <clang/Basic/Diagnostic.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/CompilerInvocation.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#pragma warning(pop)