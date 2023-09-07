#pragma once
#include <vector>
#include <string>

#include "llvm_precomp.h"

bool generate_shellcode(std::string contents, std::vector<std::string> args = {});