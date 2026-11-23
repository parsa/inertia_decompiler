"""Layer: release evidence. Responsibility: compare unchanged corpus C to original x86 bytes."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from struct import pack, unpack_from
from subprocess import run

import unicorn as u
from unicorn import x86_const as x

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXE = ROOT / "EXE/PRINCE.EXE"
DS, SS, SP = 0x3300, 0x4400, 0xFE00
RET_CS, RET_IP = 0x5100, 0x1234
REGISTERS = dict(EAX=0xBEEF1357, EBX=0xA55A2468, EBP=0x13572468,
                 ESP=0x2468FE00, EFLAGS=0x0203)


@dataclass(frozen=True)
class Case:
    """One fixed register/memory fixture and the exact release artifact coordinate."""
    name: str
    target: int
    size: int
    memory: dict[tuple[int, int], int]
    index: int = 0
    owner: int = 0

    @property
    def initial_words(self) -> dict[tuple[int, int], int]:
        """Return data sentinels and a far-return frame, including a saved-BP guard."""
        frame = {(SS, SP - 2): 0x7777, (SS, SP): RET_IP, (SS, SP + 2): RET_CS,
                 (SS, SP + 4): self.index, (SS, SP + 6): self.owner}
        return self.memory | frame


CELLS = tuple(range(0x5CE6, 0x5E26, 0x40))
CLEAR = Case("1283c-stride", 0x1283C, 18, {
    (DS, addr + delta): 0x8100 + 16 * i + delta
    for i, addr in enumerate((*CELLS, 0x5E26)) for delta in (-2, 0, 2)
})
LINKS = {(DS, 0x0250): 0x0300, (DS, 0x0300): 0, (DS, 0): 0x4D00,
         (DS, 0x4D00): 0x6060}
NULL = Case("29b99-null", 0x29B99, 28, LINKS, index=3, owner=0x0200)
NULL_AT_COUNT = Case("29b99-null-at-count", 0x29B99, 28, LINKS, index=2, owner=0x0200)
COUNTED = Case("29b99-counted-control", 0x29B99, 28, LINKS, index=1, owner=0x0200)


def native(case: Case, body: bytes) -> list[str]:
    """Execute original bytes and capture ordered data/stack effects and branch states."""
    cpu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_16)
    cpu.mem_map(0, 0x100000)
    cpu.mem_write(case.target, body)
    cleanup = 0 if case.target == 0x1283C else 4
    retf = case.target + len(body) - (1 if cleanup == 0 else 3)
    assert body[retf - case.target:] == (b"\xcb" if cleanup == 0 else b"\xca\x04\x00")
    cs = (case.target >> 16) << 12
    ip = case.target & 0xFFFF
    for reg, value in (REGISTERS | dict(CS=cs, IP=ip, DS=DS, SS=SS)).items():
        cpu.reg_write(getattr(x, f"UC_X86_REG_{reg}"), value)
    words = case.initial_words
    for (segment, offset), value in words.items():
        cpu.mem_write((segment << 4) + offset, pack("<H", value))

    lines: list[str] = []
    current = 0

    def code(uc: u.Uc, address: int, size: int, _data: object) -> None:
        nonlocal current
        current = address
        assert case.target <= address <= retf, (hex(address), lines[-9:])
        ax = uc.reg_read(x.UC_X86_REG_AX)
        bx = uc.reg_read(x.UC_X86_REG_BX)
        flags = uc.reg_read(x.UC_X86_REG_EFLAGS)
        lines.append(f"INS {address:05x} {bytes(uc.mem_read(address, size)).hex()} AX={ax:04x} BX={bx:04x} FLAGS={flags:04x}")

    def mem(uc: u.Uc, kind: int, address: int, size: int, value: int, _data: object) -> None:
        write = kind == u.UC_MEM_WRITE
        # This fixture overlaps DS and SS in linear memory. Classify by the
        # decoded instruction's default segment, not by the linear address.
        segment, space = (DS, "DS") if current == 0x29BA4 else (SS, "SS")
        offset = address - (segment << 4)
        assert 0 <= offset < 0x10000 and size == 2, (hex(current), hex(address), size)
        if write:
            value &= (1 << (size * 8)) - 1
        else:
            value = int.from_bytes(uc.mem_read(address, size), "little")
        lines.append(f"{space} {'W' if write else 'R'} {segment:04x}:{offset:04x} {size} {value:04x}")

    cpu.hook_add(u.UC_HOOK_CODE, code)
    cpu.hook_add(u.UC_HOOK_MEM_READ | u.UC_HOOK_MEM_WRITE, mem)
    cpu.emu_start(case.target, retf, count=80)
    assert (cpu.reg_read(x.UC_X86_REG_CS) << 4) + cpu.reg_read(x.UC_X86_REG_IP) == retf
    assert cpu.reg_read(x.UC_X86_REG_SP) == SP
    before = len(lines)
    cpu.emu_start(retf, 0, count=1)
    assert lines[before].startswith(f"INS {retf:05x} ")
    assert lines[before + 1:] == [
        f"SS R {SS:04x}:{SP:04x} 2 {RET_IP:04x}",
        f"SS R {SS:04x}:{SP + 2:04x} 2 {RET_CS:04x}",
    ]
    values = {reg: cpu.reg_read(getattr(x, f"UC_X86_REG_{reg}")) for reg in REGISTERS | dict(CS=0, IP=0)}
    # Unicorn can report the old offset after real-mode RETF. Take the logical IP
    # from the observed first stack read, as test_inertia_wait_sound_idle_native does.
    frame_ip = int(lines[before + 1].split()[-1], 16)
    lines.append(f"RETF IP raw-unicorn={values['IP']:04x} observed-frame={frame_ip:04x}")
    values["IP"] = frame_ip
    state = " ".join(f"{reg}={values[reg]:08x}" for reg in ("EAX", "EBX", "EBP", "ESP"))
    lines.append(f"EXIT {state} FLAGS={values['EFLAGS']:04x} CS:IP={values['CS']:04x}:{values['IP']:04x}")
    for segment, offset in words:
        value = int.from_bytes(cpu.mem_read((segment << 4) + offset, 2), "little")
        lines.append(f"FINAL {segment:04x}:{offset:04x} {value:04x}")
    return lines


def host(case: Case) -> list[str]:
    """Run the unchanged generated C against the same DS words and initial ABI."""
    words = case.initial_words
    inputs = [case.target, DS, SS, *REGISTERS.values(), len(words)]
    for (segment, offset), value in words.items():
        inputs += [segment, offset, value]
    for segment, offset in words:
        inputs += [segment, offset]
    payload = " ".join(f"{value:x}" for value in inputs) + "\n"
    (HERE / f"{case.name}.stdin").write_text(payload)
    return run([HERE / "host"], input=payload, text=True, capture_output=True,
               check=True, timeout=5).stdout.splitlines()


def main() -> None:
    """Write reproducible traces and require the expected differential observations."""
    image = EXE.read_bytes()
    mz_header_size = unpack_from("<H", image, 8)[0] * 16
    assert image[:2] == b"MZ" and mz_header_size == 0x2000
    print(f"native={EXE} sha256={sha256(image).hexdigest()} unicorn={u.__version__}")
    suites = (
        (CLEAR, [f"DS W 3300:{addr:04x} 2 0000" for addr in CELLS],
         ["DS W 3300:5ce6 2 0000"] * 4, "beef1357 a55a5e26", "beef1357 a55a5de6"),
        (NULL, ["DS R 3300:0250 2 0300", "DS R 3300:0300 2 0000"],
         ["DS R 3300:0250 2 0300", "DS R 3300:0300 2 0000", "DS R 3300:0000 2 4d00"],
         "beef0000 a55a0001", "beef4d00 a55a4d00"),
        (NULL_AT_COUNT, ["DS R 3300:0250 2 0300", "DS R 3300:0300 2 0000"],
         ["DS R 3300:0250 2 0300", "DS R 3300:0300 2 0000"],
         "beef0000 a55a0001", "beef0000 a55a0000"),
        (COUNTED, ["DS R 3300:0250 2 0300"], ["DS R 3300:0250 2 0300"],
         "beef0300 a55a0001", "beef0300 a55a0300"),
    )
    for case, expected_native, expected_host, want_native, want_host in suites:
        file_offset = case.target - 0x10000 + mz_header_size
        body = image[file_offset:file_offset + case.size]
        print(f"{case.name} file=0x{file_offset:x} bytes={body.hex()} index={case.index:04x} owner={case.owner:04x}")
        setup = [f"DS={DS:04x} SS={SS:04x}", *(f"{k}={v:08x}" for k, v in REGISTERS.items()),
                 *(f"INIT {s:04x}:{o:04x} {v:04x}" for (s, o), v in case.initial_words.items())]
        for variant, lines, expected, want in (("native", native(case, body), expected_native, want_native),
                                                ("release-c", host(case), expected_host, want_host)):
            entry = f"NATIVE ENTRY CS:IP={(case.target >> 16) << 12:04x}:{case.target & 0xffff:04x}"
            preamble = setup + ([entry] if variant == "native" else [])
            (HERE / f"{case.name}.{variant}.trace").write_text("\n".join(preamble + lines) + "\n")
            data = [line for line in lines if line.startswith("DS ")]
            state = next(line for line in lines if line.startswith("EXIT "))
            a, b = want.split()
            assert data == expected, (case.name, variant, data, expected)
            assert f"EAX={a} EBX={b} EBP=13572468 ESP=2468{0xFE04 if case is CLEAR else 0xFE08:04x}" in state, state
            assert state.endswith("CS:IP=5100:1234"), state
            print(f"  {variant} {len(data)} DS effects; {state}")


if __name__ == "__main__":
    main()
