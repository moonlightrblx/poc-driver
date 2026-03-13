#include "imports.h"
#include "functions.h"
uintptr_t pattern_scan(uintptr_t base, size_t size, const char* pattern, const char* mask)
{
	size_t pattern_len = strlen(mask);

	for (size_t i = 0; i <= size - pattern_len; i++)
	{
		bool found = true;

		for (size_t j = 0; j < pattern_len; j++)
		{
			if (mask[j] != '?' &&
				pattern[j] != *(char*)(base + i + j))
			{
				found = false;
				break;
			}
		}

		if (found)
			return /*base + */ i;
	}

	return 0;
}
auto driver_unload(PDRIVER_OBJECT driver_object) -> void
{
	dbg("driver unloaded!\n");
}

auto driver_entry() -> const NTSTATUS
{
	ctx g_ctx;
	dbg("\n\n\nat driver entry!\n");
	size_t size = 0;
	auto win32k = utils::get_kernel_module("win32k.sys", &size);

	if (!win32k) {
		dbg("win32k not found!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	dbg("win32k base address: 0x%llX\n", win32k);

	// win 10 sig (22h2)
	// 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? 4C 8B 54 24 ? 4C 89 54 24 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4 ? C3 ? ? ? ? ? ? ? ? ? 48 83 EC ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? FF 15 ? ? ? ? 48 83 C4
	// win 11 sig (tested on 24h2) 
	// 48 89 5C 24 ? 57 48 83 EC ? 48 8B DA 8B F9 E8 ? ? ? ? 4C 8B 80 ? ? ? ? 49 8B 80 ? ? ? ? 48 8B 40 ? 48 85 C0 74 ? 48 8B D3 8B CF E8 ? ? ? ? 48 8B 5C 24 ? 48 83 C4 ? 5F C3 ? EB ? ? ? ? ? ? ? ? ? ? 48 89 5C 24 ? 57

	const char* win32k_sig = "\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x4C\x8B\x54\x24\x00\x4C\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x48\x83\xEC";
	const char* win32k_mask = "xxxx?xxxxx?xxxxx????xxx????xxx?xx?????xxxxxx?xxx???x?xxx?xxxx?xxxxx??????xxxxxx?xxxx??xxxxxx?xxxxx??????xxxx??x";

	const char* w_11_win32k_sig = "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xDA\x8B\xF9\xE8\x00\x00\x00\x00\x4C\x8B\x80\x00\x00\x00\x00\x49\x8B\x80\x00\x00\x00\x00\x48\x8B\x40\x00\x48\x85\xC0\x74\x00\x48\x8B\xD3\x8B\xCF\xE8\x00\x00\x00\x00\x48\x8B\x5C\x24\x00\x48\x83\xC4\x00\x5F\xC3\x00\xEB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x89\x5C\x24\x00\x57";
	const char* w_11_win32k_mask = "xxxx?xxxx?xxxxxx????xxx????xxx????xxx?xxxx?xxxxxx????xxxx?xxx?xx?x??????????xxxx?x";

	//// todo: finish sig scans
	uintptr_t addr = pattern_scan(
		win32k,
		size,
		w_11_win32k_sig,
		w_11_win32k_mask
	);

	if (!addr) {
		g_ctx.win_11 = false;
		addr = pattern_scan(
			win32k,
			size,
			win32k_sig,
			win32k_mask
		);
		if (!addr) {
			dbg("failed to find function offset!\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}
	}
	dbg("function offset: 0x%llX\n", addr);
	// [-] function offset: 0xCE3C  22h4
	// [-] function offset: 0x664E8 22h1

	g_ctx.hook_address = win32k + addr; // sig scan offset

	dbg("g_ctx->hook_address: 0x%llX\n", g_ctx.hook_address);

	g_ctx.func_bytes = *reinterpret_cast<uintptr_t*>(g_ctx.hook_address); // get the first 8 bytes of the function
	// fud method <3 (jk)
	*reinterpret_cast<uintptr_t*>(g_ctx.hook_address) = reinterpret_cast<uintptr_t>(&hooked_function);


	uint8_t* bytes = reinterpret_cast<uint8_t*>(g_ctx.hook_address);

	dbg("func bytes: ");
	for (int i = 0; i < 8; i++) {
		DbgPrintEx(0, 0, "%02X ", bytes[i]);
	}

	DbgPrintEx(0, 0, "\n");

	dbg("success!\n");

	return STATUS_SUCCESS;
}