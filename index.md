---
layout: default
---

# Bypassing MmMapIoSpace Page-Table Protection via MMPFN Manipulation

**Making `MmMapIoSpaceEx` map page-table pages by toggling a single bit in the PFN database.**

---

## TL;DR

- `MmMapIoSpaceEx` refuses to map certain critical physical pages —
  including page-table pages (PML4, PDPT, PD, PT) — because the
  memory manager checks the **MMPFN** entry for the requested PFN
  and rejects it if it looks like a page-table page.
- The check inspects the `PrototypePte` bit (bit 63) of the MMPFN's
  `PteFrame` field. When this bit is clear on a page-table page, the
  kernel recognizes it as a critical structure and blocks the mapping.
- **By setting this single bit before calling `MmMapIoSpaceEx`, the
  validation is bypassed.** The kernel no longer identifies the page
  as a page-table page and allows the mapping to proceed.
- After the mapping is established, clear the bit back — the mapping
  persists but the MMPFN is restored to its original state.
- This turns any BYOVD driver that exposes `MmMapIoSpaceEx` (or any
  physical-to-kernel-VA mapping primitive) into a page-table R/W
  channel, even though Microsoft specifically added protection to
  prevent that.
- Other bits in the MMPFN may also work — I did not continue reversing
  every code path, but the `PrototypePte` bit is confirmed effective
  on current Win11 builds.

---

## 1. Background: why MmMapIoSpace blocks page-table pages

`MmMapIoSpaceEx` is the kernel API for mapping a physical address
range into kernel virtual address space. It is the standard way to
access memory-mapped I/O regions, and it's the function most BYOVD
(Bring Your Own Vulnerable Driver) exploits call to get a kernel VA
for an arbitrary physical address.

Microsoft is aware of this abuse pattern. As a mitigation, the memory
manager added a check: before completing the mapping, it consults the
**PFN database** (`MmPfnDatabase`) to determine what kind of page the
physical address belongs to. If the target PFN corresponds to a
page-table page — part of the x86-64 paging hierarchy that the kernel
uses for virtual-to-physical translation — the call is rejected.

The intent is clear: even if an attacker has a BYOVD primitive that
lets them call `MmMapIoSpaceEx` at will, they should not be able to
map page-table pages and modify page-table entries directly. Doing so
would give them full arbitrary R/W of physical memory (by remapping
PTEs to point at any physical page) and complete control over the
virtual address space of any process.

## 2. The PFN database and MMPFN structure

Every physical page in the system has a corresponding **MMPFN** entry
in the PFN database. `MmPfnDatabase` is a kernel global that points
to an array of MMPFN structures, one per PFN (page frame number).
Given a physical address, the PFN is simply `PhysAddr >> 12`, and
the MMPFN entry is at `MmPfnDatabase[PFN]`.

The MMPFN structure (0x30 bytes on current Win11 builds) contains
metadata about each physical page:

| Offset | Field | Description |
|--------|-------|-------------|
| `0x00` | `u1` | Flags / containing process info |
| `0x08` | `PteAddress` | Kernel VA of the PTE that maps this page |
| `0x18` | `u3` (lock + refcount) | Spinlock (bit 63) and reference count |
| `0x22` | `PageLocation` | Page state (Active, Standby, Free, etc.) |
| `0x28` | `PteFrame` | PFN of the page table that contains the PTE mapping this page, plus flags in the high bits |

The field that matters is `PteFrame` at offset `0x28`. It is a
64-bit value where:

- The lower bits encode the PFN of the parent page table
- **Bit 63** is the `PrototypePte` flag

## 3. The bypass: flipping PrototypePte

When `MmMapIoSpaceEx` (or the internal routines it calls) checks
whether a physical page is a page-table page, it examines the
MMPFN entry. The `PrototypePte` bit (bit 63 of `PteFrame`) is
part of how the kernel classifies the page. A page-table page
will have this bit clear, which (combined with other classification
logic) causes the mapping to be rejected.

The bypass is trivial:

```cpp
// 1. Locate the MMPFN entry for the target page-table PFN
uint64_t target_pfn    = page_table_phys >> 12;
uint64_t mmpfn_addr    = MmPfnDatabase + target_pfn * 0x30;

// 2. Read the PteFrame field at offset 0x28
uint64_t* pte_frame    = (uint64_t*)(mmpfn_addr + 0x28);
uint64_t  original     = *pte_frame;

// 3. Set the PrototypePte bit (bit 63)
*pte_frame |= 0x8000000000000000ULL;

// 4. Now MmMapIoSpaceEx succeeds on the page-table page
void* mapped = MmMapIoSpaceEx(page_table_phys, PAGE_SIZE, PAGE_READWRITE);

// 5. Clear the bit back — the mapping persists
*pte_frame = original;
```

That's it. Set bit 63, call the mapping function, clear bit 63.
The mapping is established and remains valid after the bit is
restored.

### Why this works

The `PrototypePte` bit tells the memory manager that this page's PTE
is a "prototype PTE" — a shared mapping used by section objects
(memory-mapped files, shared memory). When the kernel sees this bit
set, it takes a different code path for page classification that
does not flag the page as a critical page-table structure. The
kernel trusts the MMPFN metadata — it has no reason to expect that
it has been modified externally, because the PFN database lives in
kernel address space.

But if you have *any* way to write to the MMPFN entry — which you do
if you already have a kernel write primitive, even a constrained one
(a BYOVD driver that lets you write a few bytes to a kernel address)
— you can flip this bit before calling the mapping function.

### The irony: the MMPFN itself is not protected

Here's the key detail that makes this entire chain work:
`MmMapIoSpaceEx` protects page-table pages from being mapped, but it
does **not** protect the MMPFN database entries that describe those
pages. The MMPFN entries live in normal kernel memory — they are not
page-table pages themselves — so `MmMapIoSpaceEx` will happily map
them.

This means a BYOVD driver that only exposes `MmMapIoSpaceEx` gives
you everything you need:

1. Use `MmMapIoSpaceEx` to map the physical page containing the
   target PFN's MMPFN entry (this succeeds — it's not a page-table
   page)
2. Flip bit 63 in the mapped MMPFN
3. Use `MmMapIoSpaceEx` again to map the actual page-table page
   (this now succeeds because you just disabled the protection)
4. Clear bit 63 back

The protection checks the MMPFN to decide whether to allow the
mapping, but the MMPFN itself is unprotected from the same mapping
primitive. The guard trusts metadata that the attacker can modify
using the exact same API the guard is trying to restrict.

## 4. Practical implications for BYOVD

Many vulnerable drivers expose some combination of:

- **Physical memory read/write** — directly via `MmMapIoSpace` or
  equivalent
- **Arbitrary kernel VA read/write** — via `MmCopyMemory` or direct
  pointer dereference
- **MSR read/write** — which can be chained into other primitives

If a driver uses `MmMapIoSpaceEx` internally, Microsoft's page-table
protection was supposed to limit the damage: you can map device
memory, you can map normal data pages, but you cannot map page-table
pages. This bypass removes that limitation.

The attack chain is:

1. **Locate `MmPfnDatabase`** — exported symbol, trivially resolved
   via `NtQuerySystemInformation(SystemModuleInformation)` + PE
   parsing of `ntoskrnl.exe`, or sigscanned from known callers.

2. **Compute the MMPFN address** for the target page-table PFN.
   The PFN database is a flat array: `MmPfnDatabase + PFN * 0x30`.

3. **Write 8 bytes** to offset `0x28` of that MMPFN entry (set
   bit 63). This requires only a single 8-byte kernel write — many
   BYOVD drivers expose this.

4. **Call `MmMapIoSpaceEx`** on the page-table's physical address.
   It now succeeds.

5. **Clear bit 63** in the MMPFN to restore original state.

6. You now have a kernel-VA-accessible mapping of a page-table page.
   Read or write any PTE in that page at will.

### What you can do with a mapped page table

Once you have R/W access to a page table:

- **Remap any PTE** to point at any physical address — instant
  arbitrary physical R/W
- **Graft a PML4E** into a target process to create a shared
  physical memory window
- **Hide page-table modifications** from integrity checks that only
  look at the PFN database (since you restored the MMPFN)
- **Build a complete page-table hierarchy** for full address-space
  control

## 5. Detection

- **MMPFN integrity monitoring.** The `PrototypePte` bit of a
  page-table page's MMPFN should never be set. A kernel-mode monitor
  that periodically scans MMPFN entries for active page-table PFNs
  and checks bit 63 would catch the manipulation — but only if it
  samples during the brief window between set and clear. A more
  robust check would verify that the `PrototypePte` bit is consistent
  with the page's actual role (page-table pages should never have it
  set).

- **PatchGuard / KPP.** As of current Windows builds, PatchGuard does
  not monitor individual MMPFN entries for bit-level tampering. This
  may change.

- **HVCI / VBS.** Virtualization-Based Security protects page tables
  via the hypervisor (Second Level Address Translation / EPT), which
  operates below the MMPFN layer. On systems with HVCI enabled,
  modifying a PTE via a mapped page-table page may trigger a #VE or
  EPT violation. The MMPFN bypass gets you the *mapping*, but writing
  to the mapped PTE may still be blocked by the hypervisor. This is
  environment-dependent.

- **ETW / driver load auditing.** The BYOVD driver load itself is
  the most detectable part of this chain. The MMPFN manipulation is
  a single 8-byte write that happens and reverts in microseconds.

## 6. Scope and limitations

- **Requires an existing kernel write primitive.** You need to be
  able to write 8 bytes to a known kernel address (the MMPFN entry).
  This isn't a standalone exploit — it's a technique that upgrades
  a constrained BYOVD primitive into a page-table R/W channel.

- **MMPFN structure offsets vary by build.** The offsets documented
  here (`PteFrame` at `0x28`, struct size `0x30`) are stable across
  Windows 10 1709 through Windows 11 26H2, but future builds could
  change them. The `PrototypePte` bit position (bit 63 of `PteFrame`)
  has been stable across all tested builds.

- **The bit must be restored.** Leaving the `PrototypePte` bit set
  on a page-table page's MMPFN may cause the memory manager to
  mishandle the page during working-set trimming, process teardown,
  or other page-state transitions. Always clear it after the mapping
  is established.

- **Other MMPFN bits may also work.** I did not exhaustively reverse
  every validation path in `MmMapIoSpaceEx`. The `PrototypePte` bit
  is the simplest and most reliable bypass I found, but there may be
  other bits or field modifications that achieve the same result
  through different code paths.

## 7. Further reading

- **Windows Internals 7e**, Yosifovich / Ionescu / Russinovich / Solomon
  — Chapter on the Memory Manager, particularly the MMPFN structure
  and page-table management.
- [**blahcat — "Some toying with the Self-Reference PML4 Entry"**](https://blahcat.github.io/2020-06-15-playing-with-self-reference-pml4-entry/)
  — Background on page-table self-referencing, which is the structure
  this bypass lets you map and modify.

---

If you know of prior public documentation of this specific MMPFN bit-flip
bypass for `MmMapIoSpace`, open an issue — I want the attribution right.
