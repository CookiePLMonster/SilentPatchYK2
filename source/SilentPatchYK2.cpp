#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include "Utils/MemoryMgr.h"
#include "Utils/Trampoline.h"
#include "Utils/Patterns.h"

TrampolineMgr trampolines;

static void InitASI()
{
	std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule( GetModuleHandle( nullptr ), ".text" );

	using namespace Memory;
	using namespace hook;

	
	// Make frame limiter busy loop so it's more accurate
	{
		auto oneUsCompare = get_pattern( "48 2B C8 48 81 F9 E8 03 00 00", 10 );
		Patch<uint8_t>( oneUsCompare, 0xEB ); // jl -> jmp
	}


	// Uncap minigames which did not need to be capped
	{
		void* noppedFpsCalls[] = {
			// Karaoke
			 get_pattern( "41 8D 4C 24 3C E8 ? ? ? ? B2 01", 5 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 90 41 B8 ? ? ? ? 48 8D 54 24 ? 48 8B CB E8 ? ? ? ? 90 4C 8B C0", 2 ),

			 // Mahjong
			 get_pattern( "8D 48 3C E8 ? ? ? ? 33 C9", 3 ),
			 get_pattern( "E8 ? ? ? ? 90 49 8B CE 4C 8D 5C 24 ? 49 8B 5B 30" ),

			 // Oicho Kabu
			 get_pattern( "B9 ? ? ? ? E8 ? ? ? ? 33 C0 48 89 83 00 07 00 00", 5 ),
			 get_pattern( "E8 ? ? ? ? 90 89 2D" ),

			 // Cee-lo/chinchiro
			 get_pattern( "E8 ? ? ? ? 90 48 8B 8B ? ? ? ? 48 85 C9 74 16" ),
			 get_pattern( "B9 ? ? ? ? E8 ? ? ? ? 90 48 8D 4C 24 48", 5 ),

			 // Tougijyo (Colliseum) menu
			 get_pattern( "8D 4B 3C E8 ? ? ? ? 48 8D 05", 3 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 90 33 D2", 2 ),

			 // Batting center
			 get_pattern( "8D 4D 3C E8 ? ? ? ? 49 8B 46 28", 3 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 48 8B 87 B0 00 00 00", 2 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B CB 48 8B 5C 24 78", 2 ),

			 // Blackjack
			 get_pattern( "8D 4B 3C E8 ? ? ? ? 48 8B CF", 3 ),
			 // The other one is below

			 // Poker
			 get_pattern( "8D 4B 3C E8 ? ? ? ? B9 40 01 00 00", 3 ),
			 // The other one is below

			 // Hanafuda/Koi-Koi
			 get_pattern( "8D 4E 3C E8 ? ? ? ? 89 B3 80 00 00 00", 3 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B 5C 24 68", 2 ),

			 // Unknown baseball game
			 get_pattern( "8D 4B 3C E8 ? ? ? ? 48 8B 46 28", 3 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B 43 28", 2 ),

			 // Unknown baseball game #2
			 get_pattern( "33 C9 E8 ? ? ? ? 90 48 8D 93 1C 03 00 00", 2 ),
			 get_pattern( "48 89 91 50 03 00 00 B9 ? ? ? ? E8 ?", 12 ),

			 // Darts
			 get_pattern( "B9 ? ? ? ? E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 58", 5 ),
			 get_pattern( "33 C9 E8 ? ? ? ? 90 48 8D 8E 30 08 00 00", 2 )
		};

		for ( void* addr : noppedFpsCalls )
		{
			Nop( addr, 5 );
		}

		// Blackjack and poker dtors
		pattern( "33 C9 E8 ? ? ? ? 90 48 8B CB 48 8B 5C 24 40" ).count(2).for_each_result( [] ( pattern_match match ) {
			Nop( match.get<void>( 2 ), 5 );
		} );
	}


	// Cap Toylets to 30FPS
	{
		auto toyletsFpsCap = get_pattern( "B9 ? ? ? ? E8 ? ? ? ? B9 07 00 00 00", 1 );
		Patch<int32_t>( toyletsFpsCap, 30 );
	}
}

// ========== Hooking boilerplate ==========
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
