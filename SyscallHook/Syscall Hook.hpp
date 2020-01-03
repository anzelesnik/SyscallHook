#pragma once

#include "Native.hpp"

bool hookSystemCall(std::uintptr_t hookFunction, std::uintptr_t systemFunction);