namespace utils
{
	uintptr_t context_cr3 = 0;

	auto get_system_information(const SYSTEM_INFORMATION_CLASS information_class) -> const void*
	{
		unsigned long size = 32;
		char buffer[32];

		ZwQuerySystemInformation(information_class, buffer, size, &size);

		const auto info = ExAllocatePool(NonPagedPool, size); // blah blah blah msvc doesnt like this functionf or some reason.

		if (!info)
		{
			return nullptr;
		}

		if (ZwQuerySystemInformation(information_class, info, size, &size) != STATUS_SUCCESS)
		{
			ExFreePool(info);
			return nullptr;
		}

		return info;
	}

	auto get_kernel_module(const char* name, size_t* size) -> const uintptr_t
	{
		const auto to_lower = [](char* string) -> const char* {
			for (char* pointer = string; *pointer != '\0'; ++pointer)
			{
				*pointer = (char)(short)tolower(*pointer);
			}

			return string;
			};

		const auto info = (PRTL_PROCESS_MODULES)get_system_information(system_module_information);

		if (!info)
		{
			return 0;
		}

		for (auto i = 0ull; i < info->number_of_modules; ++i)
		{
			const auto& module = info->modules[i];

			if (strcmp(to_lower((char*)module.full_path_name + module.offset_to_file_name), name) == 0)
			{
				const auto address = module.image_base;
				*size = module.image_size;
				ExFreePool(info);

				return reinterpret_cast<uintptr_t>(address);
			}
		}

		ExFreePool(info);

		return 0;
	}


	//from https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html
	DWORD getoffsets()
	{
		RTL_OSVERSIONINFOW ver = { 0 };
		RtlGetVersion(&ver);

		switch (ver.dwBuildNumber)
		{
		case WINDOWS_1803:
			return 0x0278;
			break;
		case WINDOWS_1809:
			return 0x0278;
			break;
		case WINDOWS_1903:
			return 0x0280;
			break;
		case WINDOWS_1909:
			return 0x0280;
			break;
		case WINDOWS_2004:
			return 0x0388;
			break;
		case WINDOWS_20H2:
			return 0x0388;
			break;
		case WINDOWS_21H1:
			return 0x0388;
			break;
		default:
			return 0x0388;
		}
	}
	/*
		why i dont use virtual memory (mmcopymemory is still dtc btw :D )
		* why this is detected and bad
		 MmCopyVirtualMemory is defined as __int64 __fastcall (__int64 a1, __int64 a2, __int64 a3, __int64 a4)
		 and calls
		 MiCopyVirtualMemory

		 MiCopyVirtualMemory calls KeStackAttachProcess which eac has no time detecting
			mov     rsi, [rsp+428h+var_3E0]
			test    rsi, rsi
			jz      loc_1409B86E5
			mov     [rsp+428h+var_3F8], edi
			lea     rdx, [rsp+428h+ApcState] ; ApcState
			mov     rcx, r12        ; PROCESS
			call    KeStackAttachProcess ; the detection ;)
			cmp     [rsp+428h+AccessMode], dil
			jz      short loc_1409B8132
			cmp     r15, r13
			jnz     short loc_1409B8132
	*/
	auto readphysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
	{
		if (!address)
			return STATUS_UNSUCCESSFUL;

		MM_COPY_ADDRESS addr = { 0 };
		addr.PhysicalAddress.QuadPart = (LONGLONG)address;


		return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, read);
	}

	auto writephysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written) -> NTSTATUS
	{
		if (!address)
			return STATUS_UNSUCCESSFUL;

		PHYSICAL_ADDRESS addr = { 0 };
		addr.QuadPart = (LONGLONG)address;

		auto mapped_mem = MmMapIoSpaceEx(addr, size, PAGE_READWRITE);

		if (!mapped_mem)
			return STATUS_UNSUCCESSFUL;

		memcpy(mapped_mem, buffer, size);

		*written = size;
		MmUnmapIoSpace(mapped_mem, size);
		return STATUS_SUCCESS;
	}

	auto translateaddress(uint64_t processdirbase, uint64_t address) -> uint64_t
	{
		processdirbase &= ~0xf;

		uint64_t pageoffset = address & ~(~0ul << PAGE_OFFSET_SIZE);
		uint64_t pte = ((address >> 12) & (0x1ffll));
		uint64_t pt = ((address >> 21) & (0x1ffll));
		uint64_t pd = ((address >> 30) & (0x1ffll));
		uint64_t pdp = ((address >> 39) & (0x1ffll));

		SIZE_T readsize = 0;
		uint64_t pdpe = 0;
		readphysaddress((void*)(processdirbase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
		if (~pdpe & 1)
			return 0;

		uint64_t pde = 0;
		readphysaddress((void*)((pdpe & mask) + 8 * pd), &pde, sizeof(pde), &readsize);
		if (~pde & 1)
			return 0;

		if (pde & 0x80)
			return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

		uint64_t ptraddr = 0;
		readphysaddress((void*)((pde & mask) + 8 * pt), &ptraddr, sizeof(ptraddr), &readsize);
		if (~ptraddr & 1)
			return 0;

		if (ptraddr & 0x80)
			return (ptraddr & mask) + (address & ~(~0ull << 21));

		address = 0;
		readphysaddress((void*)((ptraddr & mask) + 8 * pte), &address, sizeof(address), &readsize);
		address &= mask;

		if (!address)
			return 0;

		return address + pageoffset;
	}

	auto readprocessmemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
	{
		auto process_dirbase = context_cr3;

		SIZE_T curoffset = 0;
		while (size)
		{
			auto addr = translateaddress(process_dirbase, (ULONG64)address + curoffset);
			if (!addr) return STATUS_UNSUCCESSFUL;

			ULONG64 readsize = min(PAGE_SIZE - (addr & 0xFFF), size);
			SIZE_T readreturn = 0;
			auto readstatus = readphysaddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), readsize, &readreturn);
			size -= readreturn;
			curoffset += readreturn;
			if (readstatus != STATUS_SUCCESS) break;
			if (readreturn == 0) break;
		}

		*read = curoffset;
		return STATUS_SUCCESS;
	}

	auto writeprocessmemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written) -> NTSTATUS
	{
		auto process_dirbase = context_cr3;

		SIZE_T curoffset = 0;
		while (size)
		{
			auto addr = translateaddress(process_dirbase, (ULONG64)address + curoffset);
			if (!addr) return STATUS_UNSUCCESSFUL;

			ULONG64 writesize = min(PAGE_SIZE - (addr & 0xFFF), size);
			SIZE_T written = 0;
			auto writestatus = writephysaddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), writesize, &written);
			size -= written;
			curoffset += written;
			if (writestatus != STATUS_SUCCESS) break;
			if (written == 0) break;
		}

		*written = curoffset;
		return STATUS_SUCCESS;
	}
}