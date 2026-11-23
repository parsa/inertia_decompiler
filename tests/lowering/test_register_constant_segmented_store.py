from types import SimpleNamespace

from capstone import CS_ARCH_X86, CS_MODE_16, Cs

from inertia.lowering import segmented_global_loads as stores


def _recover(monkeypatch, code: str, block_entries: set[int]):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    window = tuple(decoder.disasm(bytes.fromhex(code), 0x1000))
    monkeypatch.setattr(stores, "_direct_global_update_blocks_8616", lambda *_: (window,))
    monkeypatch.setattr(stores, "_capstone_insns_for_direct_global_update_8616", lambda _, block: block)
    function = SimpleNamespace(addr=0x1000, block_addrs_set=block_entries)
    return stores._recover_direct_segmented_global_store_evidence_uncached_8616(object(), function)


def test_preheader_bx_constant_does_not_prove_recurrent_store(monkeypatch):
    # mov bx,200; add bx,40; mov [bx-40],0; cmp bx,300; jb add; retf
    assert _recover(monkeypatch, "bb0002 83c340 c747c00000 81fb0003 72f2 cb", {0x1000, 0x1003}) == ()


def test_missing_cfg_entries_cannot_prove_register_derived_store(monkeypatch):
    assert _recover(monkeypatch, "bb0002 c7070000 cb", set()) == ()


def test_same_basic_block_constant_still_proves_nonloop_store(monkeypatch):
    facts = _recover(monkeypatch, "bb0002 83c340 c747c00000 cb", {0x1000})
    assert [(fact.offset, fact.width, fact.immediate_value) for fact in facts] == [(0x200, 2, 0)]


def test_iteration_local_definition_still_proves_recurrent_store(monkeypatch):
    # Loop header resets BX before the memory operand on every visit.
    facts = _recover(monkeypatch, "90 bb0002 83c340 c747c00000 e9f2ff", {0x1000, 0x1001})
    assert [(fact.offset, fact.width, fact.immediate_value) for fact in facts] == [(0x200, 2, 0)]
