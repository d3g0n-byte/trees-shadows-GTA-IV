#include "Hooking.Patterns-master/Hooking.Patterns.h"
#include "injector/injector.hpp"
#include <Windows.h>

#include "new_global_params.h"

int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved ) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		new_global_params::init();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

