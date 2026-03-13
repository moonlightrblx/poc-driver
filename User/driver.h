#pragma once

class _driver
{
private:
	typedef INT64(*Nt_UserGetPointerProprietaryId)(uintptr_t);
	Nt_UserGetPointerProprietaryId NtUserGetPointerProprietaryId = nullptr;

#define DRIVER_READVM				0x80000001
#define DRIVER_BASE				0x80000002


	int _processid;

	struct _requests
	{
		//rw
		uint32_t    src_pid;
		uint64_t    src_addr;
		uint64_t    dst_addr;
		size_t        size;

		//function requests
		int request_key;

		uintptr_t base;
	};

	auto readvm(uint32_t src_pid, uint64_t src_addr, uint64_t dst_addr, size_t size) -> void
	{
		if (src_pid == 0 || src_addr == 0) return;

		_requests out = { src_pid, src_addr, dst_addr, size, DRIVER_READVM };
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
	}

public:
	auto initdriver(int processid) -> void
	{
		/*
		* 4C 8B D1 B8 ? ? ? ? F6 04 25 ? ? ? ? ? 75 ? 0F 05 C3 CD ? C3 (maybe the sig?)
		__int64 NtUserGetPointerProprietaryId()
		{
		  __int64 result; // rax

		  result = 5217i64;
		  if ( (MEMORY[0x7FFE0308] & 1) != 0 )
			__asm { int     2Eh; DOS 2+ internal - EXECUTE COMMAND }
		  else
			__asm { syscall; Low latency system call }
		  return result;
		}
		*/

		// this is lowk NOT the method it would be better to directly call the syscall xD
		NtUserGetPointerProprietaryId = (Nt_UserGetPointerProprietaryId)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserGetPointerProprietaryId");
		if (NtUserGetPointerProprietaryId != 0)
		{
			printf("NtUserGetPointerProprietaryId: %p\n", NtUserGetPointerProprietaryId);
			_processid = processid;
		}
	}

	auto base() -> uintptr_t
	{
		_requests out = { 0 };
		out.request_key = DRIVER_BASE;
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
		return out.base;
	}

	template <typename T>
	T read(uintptr_t src, size_t size = sizeof(T))
	{
		T buffer;
		readvm(_processid, src, (uintptr_t)&buffer, size);
		return buffer;
	}

	template<typename T>
	void readarray(uint64_t address, T* array, size_t len)
	{
		readvm(_processid, address, (uintptr_t)&array, sizeof(T) * len);
	}

};

_driver driver;
