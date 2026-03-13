#pragma once

auto readvm(_requests* in) -> bool
{
	PEPROCESS source_process = NULL;
	if (in->src_pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
	if (status != STATUS_SUCCESS) return false;

	size_t memsize = 0;

	if (!NT_SUCCESS(utils::readprocessmemory(source_process, (void*)in->src_addr, (void*)in->dst_addr, in->size, &memsize)))
		return false;

	ObDereferenceObject(source_process);

	return true;
}




auto find_base(_requests* in) -> bool {
	PEPROCESS source_process = NULL;
	if (in->src_pid == 0) return false;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)in->src_pid, &source_process);
	if (status != STATUS_SUCCESS) return false;

	PEB* peb = PsGetProcessPeb(source_process);
	if (!peb) {
		ObDereferenceObject(source_process);
		return false;
	}
	// easier than whatever other public methods there are 
	// this CAN be spoofed tho and doing that will infact bsod you if the address is outside of valid memory
	void* base_address = peb->image_base_address;

	if (base_address) {
		*(void**)in->dst_addr = base_address;
	}

	ObDereferenceObject(source_process);

	return base_address != NULL;
}


auto requesthandler(_requests* pstruct) -> bool
{
	switch (pstruct->request_key) {

	case DRIVER_BASE:
		return find_base(pstruct);

	case DRIVER_READVM:
		return readvm(pstruct);
	default:
		break;
	}

	return true;
}

__int64 __fastcall hooked_function(unsigned int a1, __int64 a2)
{
	// ignore arg 2 :D
	_requests* in = (_requests*)a1; // invalid calls or invalid structs = bsod with this btw 🥹

	// todo: handle malformed requests (not ours)
	requesthandler(in);
	return 0;
}
