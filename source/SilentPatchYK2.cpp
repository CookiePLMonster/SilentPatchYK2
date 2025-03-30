#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include "Utils/HookEach.hpp"
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

	template<bool force>
	struct MinigameFPSCap
	{
		template<std::size_t Index>
		static inline void (*orgSetMinigameFPSCap)(int cap);

		static void ToggleFPSCap()
		{
			if constexpr (force)
			{
				userFPSCap_ForMinigame = 0;
			}
			else
			{
				userFPSCap_ForMinigame = userFPSCap;
			}
			minigameFPSForced = force;		
		}

		template<std::size_t Index>
		static void SetMinigameFPSCap_ForcedFPS( int cap )
		{
			orgSetMinigameFPSCap<Index>( cap );
			ToggleFPSCap();
		}

		HOOK_EACH_INIT_CTR(M2, 0, orgSetMinigameFPSCap, SetMinigameFPSCap_ForcedFPS);
		HOOK_EACH_INIT_CTR(VF5, 1, orgSetMinigameFPSCap, SetMinigameFPSCap_ForcedFPS);
		HOOK_EACH_INIT_CTR(Karaoke, 2, orgSetMinigameFPSCap, SetMinigameFPSCap_ForcedFPS);
	};
};


void OnInitializeHook()
{
	std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule( GetModuleHandle( nullptr ), ".text" );

	using namespace Memory;
	using namespace hook::txn;

	
	// Make frame limiter busy loop so it's more accurate
	try
	{
		auto oneUsCompare = get_pattern( "48 2B C8 48 81 F9 E8 03 00 00", 10 );
		Patch<uint8_t>( oneUsCompare, 0xEB ); // jl -> jmp
	}
	TXN_CATCH();


	// Uncap minigames which did not need to be capped

	// Mahjong
	try
	{
		auto ctor = get_pattern( "8D 48 3C E8 ? ? ? ? 33 C9", 3 );
		auto dtor = get_pattern( "E8 ? ? ? ? 90 49 8B CE 4C 8D 5C 24 ? 49 8B 5B 30" );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Oicho Kabu
	try
	{
		auto ctor = get_pattern( "B9 ? ? ? ? E8 ? ? ? ? 33 C0 48 89 83 00 07 00 00", 5 );
		auto dtor = get_pattern( "E8 ? ? ? ? 90 89 2D" );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Cee-lo/chinchiro
	try
	{
		auto ctor = get_pattern( "E8 ? ? ? ? 90 48 8B 8B ? ? ? ? 48 85 C9 74 16" );
		auto dtor = get_pattern( "B9 ? ? ? ? E8 ? ? ? ? 90 48 8D 4C 24 48", 5 );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Tougijyo (Colliseum) menu
	try
	{
		auto ctor = get_pattern( "8D 4B 3C E8 ? ? ? ? 48 8D 05", 3 );
		auto dtor = get_pattern( "33 C9 E8 ? ? ? ? 90 33 D2", 2 );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Batting center
	try
	{
		auto ctor1 = get_pattern( "8D 4D 3C E8 ? ? ? ? 49 8B 46 28", 3 );
		auto ctor2 = get_pattern( "33 C9 E8 ? ? ? ? 48 8B 87 B0 00 00 00", 2 );
		auto dtor = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B CB 48 8B 5C 24 78", 2 );

		Nop(ctor1, 5);
		Nop(ctor2, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Poker & Blackjack
	try
	{
		auto blackjack_ctor = get_pattern( "8D 4B 3C E8 ? ? ? ? 48 8B CF", 3 );
		auto poker_ctor = get_pattern( "8D 4B 3C E8 ? ? ? ? B9 40 01 00 00", 3 );
		auto dtors = pattern( "33 C9 E8 ? ? ? ? 90 48 8B CB 48 8B 5C 24 40" ).count(2);

		Nop(blackjack_ctor, 5);
		Nop(poker_ctor, 5);

		dtors.for_each_result( [] ( pattern_match match ) {
			Nop( match.get<void>( 2 ), 5 );
		} );
	}
	TXN_CATCH();

	// Hanafuda/Koi-Koi
	try
	{
		auto ctor = get_pattern( "8D 4E 3C E8 ? ? ? ? 89 B3 80 00 00 00", 3 );
		auto dtor = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B 5C 24 68", 2 );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Unknown baseball game
	try
	{
		auto ctor = get_pattern( "8D 4B 3C E8 ? ? ? ? 48 8B 46 28", 3 );
		auto dtor = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B 43 28", 2 );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Unknown baseball game #2
	try
	{
		auto ctor = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8D 93 1C 03 00 00", 2 );
		auto dtor = get_pattern( "48 89 91 50 03 00 00 B9 ? ? ? ? E8", 12 );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();

	// Darts
	try
	{
		auto ctor = get_pattern( "B9 ? ? ? ? E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 58", 5 );
		auto dtor = get_pattern( "33 C9 E8 ? ? ? ? 90 48 8D 8E 30 08 00 00", 2 );

		Nop(ctor, 5);
		Nop(dtor, 5);
	}
	TXN_CATCH();


	// Cap Toylets to 30FPS
	try
	{
		auto toyletsFpsCap = get_pattern( "B9 ? ? ? ? E8 ? ? ? ? B9 07 00 00 00", 1 );
		Patch<int32_t>( toyletsFpsCap, 30 );
	}
	TXN_CATCH();


	// Force 60FPS cap on arcade games even if 30FPS is selected in options
	try
	{
		using namespace ForcedMinigameFPS;

		Trampoline* trampoline = Trampoline::MakeTrampoline( GetModuleHandle( nullptr ) );

		auto setFPSCap = get_pattern( "EB 02 33 C9 E8 ? ? ? ? 4C 8B 05", 4 );
		auto tickUserFPSCheck = get_pattern( "48 8B 15 ? ? ? ? 85 D2", 3 );

		auto TrampolineInterceptCall = [trampoline](auto address, auto&& func, auto&& hook)
			{
				InterceptCall(address, func, trampoline->Jump(hook));
			};

		TrampolineInterceptCall(setFPSCap, orgSetUserFPSCap, SetUserFPSCap_ForcedFPS);
		WriteOffsetValue(tickUserFPSCheck, &userFPSCap_ForMinigame); // This comes from the Trampoline memory!

		// M2 games
		try
		{
			std::array<void*, 1> enableCap { get_pattern( "E8 ? ? ? ? 44 88 64 24 40" ) };
			std::array<void*, 1> disableCap { get_pattern( "33 C9 E8 ? ? ? ? 90 48 8D 8B 00 03 00 00", 2 ) };

			MinigameFPSCap<true>::HookEach_M2(enableCap, TrampolineInterceptCall);
			MinigameFPSCap<false>::HookEach_M2(disableCap, TrampolineInterceptCall);
		}
		TXN_CATCH();

		// VF5
		try
		{
			std::array<void*, 1> enableCap { get_pattern( "41 8D 4E 3C E8", 4 ) };
			std::array<void*, 1> disableCap { get_pattern( "33 C9 E8 ? ? ? ? 90 48 8B 8B 10 03 00 00", 2 ) };

			MinigameFPSCap<true>::HookEach_VF5(enableCap, TrampolineInterceptCall);
			MinigameFPSCap<false>::HookEach_VF5(disableCap, TrampolineInterceptCall);
		}
		TXN_CATCH();

		// Karaoke
		try
		{
			std::array<void*, 1> enableCap { get_pattern( "41 8D 4C 24 3C E8 ? ? ? ? B2 01", 5 ) };
			std::array<void*, 1> disableCap { get_pattern( "33 C9 E8 ? ? ? ? 90 41 B8 ? ? ? ? 48 8D 54 24 ? 48 8B CB E8 ? ? ? ? 90 4C 8B C0", 2 ) };

			MinigameFPSCap<true>::HookEach_Karaoke(enableCap, TrampolineInterceptCall);
			MinigameFPSCap<false>::HookEach_Karaoke(disableCap, TrampolineInterceptCall);
		}
		TXN_CATCH();
	}
	TXN_CATCH();
}
