## overview (ai generated cause im lazy)

This project is a **POC Windows kernel driver** targeting **Windows 22H1** that demonstrates **kernel ↔ usermode communication** by **hooking `NtUserGetPointerProprietaryId` inside win32k**.

Instead of using a device object or IOCTLs, communication is performed by **directly calling the hooked Win32k syscall from usermode**, passing a request structure via a single pointer argument.

* **Windows version:** 22H1
* **Architecture:** x64
* **Subsystem:** win32k / win32u
* **(research / POC)**
---


## hooking method

* **Hook type:** Direct function overwrite
* **Target:** `NtUserGetPointerProprietaryId`
* **Location:** win32k (resolved in kernel memory at runtime)

The driver locates the target function in memory and overwrites its entry to redirect execution to a custom handler.

---
# communication
Usermode resolves the syscall dynamically:

```
NtUserGetPointerProprietaryId = GetProcAddress(
    LoadLibraryA("win32u.dll"),
    "NtUserGetPointerProprietaryId"
);
```

The syscall is then invoked with a **single pointer argument** that references a custom request structure allocated in usermode.

---

### supported requests

| Request Key  | Description                         |
| ------------ | ----------------------------------- |
| `0x80000001` | Read virtual memory (cross-process) |
| `0x80000002` | Query target process base address   |

---

## driver loading

* Driver loading is **not in this project**
* No service creation or mapper logic is included
* This README intentionally does not document the loading mechanism

---

## cleanup & stability
* No persistent kernel state is kept
* No device objects or symbolic links are created

---

## limitations

* POC only - not hardened
* No PatchGuard bypass logic
* No version-agnostic symbol resolution
* Relies on 22H1-specific offsets
* No validation against malformed usermode input

---

## reversing 

all reversing files are in the "reversing" folder :)

---

## disclaimer

This project is for **educational and research purposes only**.

It demonstrates kernel hooking and unconventional communication mechanisms in a controlled context.
