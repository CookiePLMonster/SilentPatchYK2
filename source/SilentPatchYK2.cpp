#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include "Utils/MemoryMgr.h"
#include "Utils/Trampoline.h"
#include "Utils/Patterns.h"
#include "Utils/ScopedUnprotect.hpp"

namespace ForcedMinigameFPS
{
	static bool minigameFPSForced = false;
	static int& userFPSCap_ForMinigame = Trampoline::MakeTrampoline( GetModuleHandle( nullptr ) )->Reference<int>();
	static int userFPSCap;

	static void (*orgSetUserFPSCap)(int cap);
	static void SetUserFPSCap_ForcedFPS( int cap )
	{
		orgSetUserFPSCap( cap );
		userFPSCap = cap;
		if ( !minigameFPSForced )
		{
			userFPSCap_ForMinigame = cap;
		}
	}

	static void (*orgSetMinigameFPSCap)(int cap);

	template<bool force>
	static void SetMinigameFPSCap_ForcedFPS( int cap )
	{
		orgSetMinigameFPSCap( cap );
		if constexpr ( force )
		{
			userFPSCap_ForMinigame = 0;
		}
		else
		{
			userFPSCap_ForMinigame = userFPSCap;
		}
		minigameFPSForced = force;
	}
};


void OnInitializeHook()
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


	// Force 60FPS cap on arcade games even if 30FPS is selected in options
	{
		using namespace ForcedMinigameFPS;

		Trampoline* trampoline = Trampoline::MakeTrampoline( GetModuleHandle( nullptr ) );

		auto enableCapTrampoline = trampoline->Jump(SetMinigameFPSCap_ForcedFPS<true>);
		auto disableCapTrampoline = trampoline->Jump(SetMinigameFPSCap_ForcedFPS<false>);

		auto setFPSCap = get_pattern( "EB 02 33 C9 E8 ? ? ? ? 4C 8B 05", 4 );
		auto tickUserFPSCheck = get_pattern( "48 8B 15 ? ? ? ? 85 D2", 3 );

		auto enableArcadeFPSCap_m2 = get_pattern( "E8 ? ? ? ? 44 88 64 24 40" );
		auto disableArcadeFPSCap_m2 = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8D 8B 00 03 00 00", 2 );

		auto enableArcadeFPSCap_vf5 = get_pattern( "41 8D 4E 3C E8", 4 );
		auto disableArcadeFPSCap_vf5 = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B 8B 10 03 00 00", 2 );

		auto enableFPSCap_Karaoke = get_pattern( "41 8D 4C 24 3C E8 ? ? ? ? B2 01", 5 );
		auto disableFPSCap_Karaoke = get_pattern( "33 C9 E8 ? ? ? ? 90 41 B8 ? ? ? ? 48 8D 54 24 ? 48 8B CB E8 ? ? ? ? 90 4C 8B C0", 2 );

		ReadCall( setFPSCap, orgSetUserFPSCap );
		InjectHook( setFPSCap, trampoline->Jump(SetUserFPSCap_ForcedFPS) );

		ReadCall( enableArcadeFPSCap_m2, orgSetMinigameFPSCap );
		InjectHook( enableArcadeFPSCap_m2, enableCapTrampoline );
		InjectHook( disableArcadeFPSCap_m2, disableCapTrampoline );

		InjectHook( enableArcadeFPSCap_vf5, enableCapTrampoline );
		InjectHook( disableArcadeFPSCap_vf5, disableCapTrampoline );

		InjectHook(enableFPSCap_Karaoke, enableCapTrampoline);
		InjectHook(disableFPSCap_Karaoke, disableCapTrampoline);

		WriteOffsetValue( tickUserFPSCheck, &userFPSCap_ForMinigame ); // This comes from Trampoline memory!
	}
}
