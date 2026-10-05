// Minimal version of an Apple-internal WebKit header, for building WebKit with MTE on with the
// public SDK. libpas includes it when it exists, and its MTE code also needs these Mach
// declarations.
#pragma once
#include <mach/mach.h>
#include <mach/mach_vm.h>
