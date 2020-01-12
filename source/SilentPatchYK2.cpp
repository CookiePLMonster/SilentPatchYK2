#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include "Utils/MemoryMgr.h"
#include "Utils/Trampoline.h"

TrampolineMgr trampolines;

static void InitASI()
{
	// Patches go here
}

// ========== Hooking boiletplate ==========
namespace HookInit
{

static void ProcHook()
{
	static bool bPatched = false;
	if ( !std::exchange(bPatched, true) )
	{
		InitASI();
	}
}

static decltype(GetCommandLineA)* pOrgGetCommandLineA;
static LPSTR WINAPI GetCommandLineA_Hook()
{
	ProcHook();
	return pOrgGetCommandLineA();
}

static uint8_t orgCode[5];
static LPSTR WINAPI GetCommandLineA_OverwritingHook()
{
	Memory::VP::Patch( pOrgGetCommandLineA, { orgCode[0], orgCode[1], orgCode[2], orgCode[3], orgCode[4] } );
	return GetCommandLineA_Hook();
}

static bool PatchIAT()
{
	const HINSTANCE hInstance = GetModuleHandle(nullptr);
	const PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);

	// Find IAT	
	PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hInstance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for ( ; pImports->Name != 0; pImports++ )
	{
		if ( _stricmp((const char*)((DWORD_PTR)hInstance + pImports->Name), "KERNEL32.DLL") == 0 )
		{
			if ( pImports->OriginalFirstThunk != 0 )
			{
				PIMAGE_IMPORT_BY_NAME* pFunctions = (PIMAGE_IMPORT_BY_NAME*)((DWORD_PTR)hInstance + pImports->OriginalFirstThunk);

				for ( ptrdiff_t j = 0; pFunctions[j] != nullptr; j++ )
				{
					if ( strcmp((const char*)((DWORD_PTR)hInstance + pFunctions[j]->Name), "GetCommandLineA") == 0 )
					{
						DWORD dwProtect;
						DWORD_PTR* pAddress = &((DWORD_PTR*)((DWORD_PTR)hInstance + pImports->FirstThunk))[j];

						VirtualProtect(pAddress, sizeof(DWORD_PTR), PAGE_READWRITE, &dwProtect);
						pOrgGetCommandLineA = **(decltype(pOrgGetCommandLineA)*)pAddress;
						*pAddress = (DWORD_PTR)GetCommandLineA_Hook;
						VirtualProtect(pAddress, sizeof(DWORD_PTR), dwProtect, &dwProtect);

						return true;
					}
				}
			}
		}
	}
	return false;
}

static bool PatchIAT_ByPointers()
{
	pOrgGetCommandLineA = GetCommandLineA;
	memcpy( orgCode, pOrgGetCommandLineA, sizeof(orgCode) );

	Trampoline& trampoline = trampolines.MakeTrampoline( pOrgGetCommandLineA );
	Memory::VP::InjectHook( pOrgGetCommandLineA, trampoline.Jump(&GetCommandLineA_OverwritingHook), PATCH_JUMP );
	return true;
}

static void InstallHooks()
{
	bool getStartupInfoHooked = PatchIAT();
	if ( !getStartupInfoHooked )
	{
		PatchIAT_ByPointers();
	}
}

}

extern "C"
{
	static LONG InitCount = 0;
	__declspec(dllexport) void InitializeASI()
	{
		if ( _InterlockedCompareExchange( &InitCount, 1, 0 ) != 0 ) return;
		HookInit::InstallHooks();
	}

	__declspec(dllexport) uint32_t GetBuildNumber()
	{
		return (rsc_RevisionID << 8) | rsc_BuildID;
	}
}
