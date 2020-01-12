workspace "SilentPatchYK2"
	platforms { "Win64" }

project "SilentPatchYK2"
	kind "SharedLib"
	targetextension ".asi"
	language "C++"

	include "source/VersionInfo.lua"
	files { "**/MemoryMgr.h", "**/Trampoline.h", "**/Patterns.*" }


workspace "*"
	configurations { "Debug", "Release", "Master" }
	location "build"

	vpaths { ["Headers/*"] = "source/**.h",
			["Sources/*"] = { "source/**.c", "source/**.cpp" },
			["Resources"] = "source/**.rc"
	}

	files { "source/*.h", "source/*.cpp", "source/resources/*.rc" }

	cppdialect "C++17"
	staticruntime "on"
	buildoptions { "/permissive-", "/sdl" }
	warnings "Extra"

	-- Automated defines for resources
	defines { "rsc_Extension=\"%{prj.targetextension}\"",
			"rsc_Name=\"%{prj.name}\"" }

filter "configurations:Debug"
	defines { "DEBUG" }
	runtime "Debug"

 filter "configurations:Master"
	defines { "NDEBUG" }
	symbols "Off"

filter "configurations:not Debug"
	optimize "Speed"
	functionlevellinking "on"
	flags { "LinkTimeOptimization" }

filter { "platforms:Win32" }
	system "Windows"
	architecture "x86"

filter { "platforms:Win64" }
	system "Windows"
	architecture "x86_64"
