#include "Hooking.Patterns-master/Hooking.Patterns.h"
#include "injector/injector.hpp"
#include <Windows.h>
#include "Vector4.h"

size_t addr_rage__grcEffect__getGlobalVar = (size_t)hook::pattern("8B 44 24 04 56 6A 00 50 E8 ? ? ? ? 8B 35 ? ? ? ? 83 C4 08 33 C9 85 F6 7E 18 BA ? ? ? ? 39 42 04 74 12 39 02 74 0E 83 C1 01 83 C2 30 3B CE 7C ED").get_first();
size_t addr_rage__grcEffect__setGlobalVarFloatVal = (size_t)hook::pattern("83 3D ? ? ? ? ? 75 5D 8B 44 24 04 85 C0 74 55 53 8B 5C 24 0C 56 8D 34 40 C1 E6 04 0F B7 86 ? ? ? ? 66 3D FF FF 8D B6 ? ? ? ? 57 8B 7C 24 18 74 12 0F B6 0E 57 51 0F B7 D0 8B CB E8 ? ? ? ? 83 C4 08 0F").get_first();

size_t addr_argExecutor__allocAndExecute = (size_t)hook::pattern("6A 00 6A 20 E8 ? ? ? ? 83 C4 08 85 C0 74 4E 8B 48 04 8B 54 24 04 C7 00 ? ? ? ? 33 0D ? ? ? ? 81 E1 ? ? ? ? 31 48 04 83 05 ? ? ? ? ? 8B 4C 24 08 C7 00 ? ? ? ? 89 50 08 D9 01 D9 58 10 D9 41 04").get_first();

namespace rage {

	class grcEffect {
	public:

		static DWORD _cdecl getGlobalVar(const char* pszName, DWORD required) {
			return ((DWORD(_cdecl*)(const char*, DWORD))addr_rage__grcEffect__getGlobalVar)(pszName, required);
		}

		// varType - is vector size like in Red Dead Redemption?
		static void _cdecl setGlobalVarFloatVal(int a, int b, int varType) {
			((void(_cdecl*)(int, int, int))addr_rage__grcEffect__setGlobalVarFloatVal)(a, b, varType);

		}
	};

}

DWORD g_dwWindParamsId = -1;
rage::Vector4 g_CurrWindParams{ 1,1,1,1 };

// GenericExecutor. ToDo.
	int argExecutor__allocAndExecute(void(_cdecl* pfnUpdate)(rage::Vector4*), rage::Vector4* pParamVec) {
		return ((int(_cdecl*)(void(_cdecl*)(rage::Vector4*), rage::Vector4*))addr_argExecutor__allocAndExecute)(pfnUpdate, pParamVec);
	}

void _cdecl setGlobalWindParams(rage::Vector4* pParamVec) {
	if (g_CurrWindParams.x != pParamVec->x || g_CurrWindParams.y != pParamVec->y || g_CurrWindParams.z != pParamVec->z || g_CurrWindParams.w != pParamVec->w) {
		memcpy(&g_CurrWindParams, pParamVec, sizeof(g_CurrWindParams));
		rage::grcEffect::setGlobalVarFloatVal(g_dwWindParamsId, (int)&g_CurrWindParams, 1);
	}
}

float* g_pWindVec = *(float**)hook::pattern(
	"F3 0F 10 05 ? ? ? ? F3 0F 11 44 24 ? F3 0F 10 05 ? ? ? ? F3 0F 11 44 24 ? F3 0F 10 05 ? ? ? ? 8D 44 24 20 50 F3 0F 11 44 24 ? F3 0F 10 05 ? ? ? ? 68 ? ? ? ? F3 0F 11 44 24 ? E8 ? ? ? ? 83 C4 08 E9 ?")
	.get_first(4); // unused in gta_trees.fxc

float* g_pWindSpeed = *(float**)hook::pattern(
	"D9 1D ? ? ? ? 83 05 ? ? ? ? ? 33 D2 38 15 ? ? ? ? 0F 84 ? ? ? ? F3 0F 10 15 ? ? ? ? F3 0F 10 0D ? ? ? ? 88 15 ? ? ? ? 33 C9 B8 ? ? ? ? 8B FF 83 CE FF 39 70 FC 74 33 8B 1D ? ? ? ?")
	.get_first(2); // noise

size_t origCall;

int _cdecl origcall_colorize(DWORD _pfn, float* pVec4) {

	// our params
	{
		rage::Vector4 vWindVals{ g_pWindVec[0],g_pWindVec[1] ,g_pWindVec[2], *g_pWindSpeed };
		argExecutor__allocAndExecute(setGlobalWindParams, &vWindVals);
	}


	// orig param
	return ((int(_cdecl*)(DWORD, float*))origCall)(_pfn, pVec4);
	return NULL;
}

void fix_it() {

	hook::pattern p("E8 ? ? ? ? 83 C4 08 68 ? ? ? ? E8 ? ? ? ? 8D 44 24 17 50 68 ? ? ? ? C6 44 24 ? ? E8 ? ? ? ?");
	if (!p.empty()) {
		size_t addr = (size_t)p.get_first();

		origCall = (*(size_t*)(addr + 1) + (addr + 5));

		injector::MakeCALL(addr, origcall_colorize);
	}
	else {
		MessageBoxA(NULL, "TEST", NULL, 0x10);
		ExitProcess(0);
	}
}
///////////////////////////

int _cdecl regNewGlobalVars(const char* pszOrigName, int b) {
	g_dwWindParamsId = rage::grcEffect::getGlobalVar("gWindParams", 0);
	rage::grcEffect::setGlobalVarFloatVal(g_dwWindParamsId, (int)&g_CurrWindParams, 1);
	char gg[0x1ff];
	//sprintf(gg, "%i", g_WindParams);
	//MessageBoxA(NULL, gg, NULL, 0x10);
	return rage::grcEffect::getGlobalVar(pszOrigName, b);
}



void hook_it() {
	hook::pattern p("E8 ? ? ? ? 6A 05 6A 01 68 ? ? ? ? 50 A3 ? ? ? ? E8 ? ? ? ? 56 68 ? ? ? ? E8 ? ? ? ? 6A 05 6A 01 68 ? ? ? ? 50 A3 ? ? ? ? E8 ? ? ? ? 83 C4 40 56");
	//hook::pattern p("E8 ? ? ? ? 56 68 ? ? ? ? E8 ? ? ? ? 6A 05 6A 01 68 ? ? ? ? 50 A3 ? ? ? ? E8 ? ? ? ? 83 C4 40 56 56 68 ? ? ? ? 56");
	if (!p.empty()) {
		size_t addr = (size_t)p.get_first();
		injector::MakeCALL(addr, regNewGlobalVars);

	}

}

void disableflag31fcheck() {
	hook::pattern p("83 FA 1F D9 6C 24 06 74 0C 8D 44 24 54 50 E8 ? ? ? ? EB 0E ");

	if (!p.empty()) {
		size_t addr = (size_t)p.get_first(2);
		injector::WriteMemory(addr, (BYTE)0x7f);
	}
}

namespace new_global_params {
	void init() {
		fix_it();
		hook_it();
		disableflag31fcheck();
	}
}