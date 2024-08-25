#!/usr/bin/env python3
from rich.segment import Segment
from textual.app import App, ComposeResult
from textual.widget import Widget
from textual.scroll_view import ScrollView
from textual.geometry import Size
from textual.widgets import Header, Footer, Static, Button
from textual.reactive import reactive
from textual.events import Click
from textual.strip import Strip

from emulator_connector import EmulatorConnector

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)

emu = EmulatorConnector(8123)

class Registers(Widget):
    gprs = [ "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
             "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra" ];

    registers: reactive[dict[str, int]] = reactive({})

    def render(self) -> str:
        text = ""
        for name in self.gprs:
            if name in self.registers.keys():
                text += f"{name}: {hex(self.registers[name])}\n"
        text += "\n\n"
        for key, value in self.registers.items():
            if key not in self.gprs:
                text += f"{key}: {hex(value)}\n"
        return text

class Disassembly(ScrollView):
    pc: reactive[int] = reactive(0)
    breakpoints: reactive[set[int]] = reactive(set())
    mode: int
    addr_mask: int

    bp = "🔴"
    muted_bp = "⭕"
    no_bp    = "  " # Two spaces since both above chars are double width?

    COMPONENT_CLASSES = {
        "address",
        "instruction-word",
        "instruction-disasm-instr",
        "instruction-disasm-args",
        "other-segment",
        "active-line",
        "inactive-line"
    }

    def __init__(self, mode = 32):
        super().__init__()
        self.mode = mode
        self.addr_mask = 0xFFFFFFFF if mode == 32 else 0xFFFFFFFFFFFFFFFF
        self.virtual_size = Size(0, (self.addr_mask + 1) >> 2)

    def scroll_to_address(self, address):
        address &= self.addr_mask
        address >>= 2
        self.scroll_to(y = address, animate = False)

    def scroll_to_address_if_needed(self, address):
        address &= self.addr_mask
        address >>= 2

        _, scroll_y = self.scroll_offset
        min_address = scroll_y
        max_address = min_address + self.size.height

        if address < min_address or address > max_address:
            self.scroll_to(y = address, animate = False)

    def scroll_to_pc(self):
        self.scroll_to_address(self.pc)

    def scroll_to_pc_if_needed(self):
        self.scroll_to_address_if_needed(self.pc)

    def on_click(self, click: Click):
        _, scroll_y = self.scroll_offset
        address = scroll_y + click.y - 1
        address <<= 2
        if address in self.breakpoints:
            emu.clear_breakpoint(address)
        else:
            emu.set_breakpoint(address)

    def render_line(self, y: int) -> Strip:
        _, scroll_y = self.scroll_offset
        address = (y + scroll_y) << 2

        active = address == (self.pc & self.addr_mask)
        active_text = "active" if active else "inactive"

        line_style = self.get_component_rich_style(f"{active_text}-line")

        address_style = self.get_component_rich_style(f"address")
        iw_style = self.get_component_rich_style(f"instruction-word")
        disasm_instr_style = self.get_component_rich_style(f"instruction-disasm-instr")
        disasm_args_style = self.get_component_rich_style(f"instruction-disasm-args")
        other_segment_style = self.get_component_rich_style(f"other-segment")

        def with_style(segment, style) -> Segment:
            for s in Segment.apply_style([segment], style, line_style.background_style):
                return s
            raise Exception("Failed to apply style to segment")

        bp_text = self.no_bp
        if address in self.breakpoints:
            bp_text = self.bp

        arrow_text = "🠶" if active else " "

        segments = [with_style(Segment(f"{bp_text}{arrow_text} "), other_segment_style)]
        segments.append(with_style(Segment(("{:08X}" if self.mode == 32 else "{:016X}").format(address)), address_style))
        segments.append(with_style(Segment("   "), other_segment_style))

        iw_text = ""
        disasm_instr_text = ""
        disasm_args_text = ""
        try:
            instr = int("0x" + emu.read_word(address), 16)
            instr_bytes = instr.to_bytes(4, "big")
            disasm = []
            for i in md.disasm(instr_bytes, address & self.addr_mask):
                disasm.append([f"{i.mnemonic}", f"{i.op_str}"])

            iw_text = "{:08X}".format(instr)
            if len(disasm) != 1:
                disasm_instr_text = f"    ERROR: len = {len(disasm)}"
            else:
                disasm_instr_text = "    " + disasm[0][0].ljust(10, ' ')
                disasm_args_text  = disasm[0][1]
        except Exception:
            iw_text = "ERROR"
            disasm_text = ""

        segments.append(with_style(Segment(iw_text), iw_style))
        segments.append(with_style(Segment(disasm_instr_text), disasm_instr_style))
        segments.append(with_style(Segment(disasm_args_text), disasm_args_style))
        width = sum([len(segment.text) for segment in segments])

        if width > self.virtual_size.width:
            self.virtual_size = self.virtual_size.with_width(width)

        return Strip(segments)

class Status(Static):
    def compose(self) -> ComposeResult:
        self.styles.layout = "horizontal"
        yield Registers()
        yield Disassembly()

    def update_state(self) -> None:
        try:
            registers = emu.registers()
            breakpoints = emu.breakpoints()

            addr_mask = self.query_one(Disassembly).addr_mask

            breakpoints_set = set()
            for breakpoint in breakpoints:
                breakpoints_set.add(breakpoint["address"] & addr_mask)

            self.query_one(Registers).registers = registers
            self.query_one(Disassembly).pc = registers["pc"]
            self.query_one(Disassembly).breakpoints = breakpoints_set

        except Exception as e:
            self.notify(f"Error updating state! {e}")

    def on_mount(self) -> None:
        emu.register_on_update_handler(self.update_state)
        self.update_state()
        self.query_one(Disassembly).scroll_to_pc_if_needed()


class Controls(Static):
    def compose(self) -> ComposeResult:
        yield Button("Step", id="step", variant="success")
        yield Button("Continue", id="continue", variant="success")
        yield Button("Break", id="break", variant="error")


class DebuggerApp(App):
    CSS_PATH = "dbg.tcss"
    BINDINGS = [
        ("s", "step", "Step"),
        ("c", "continue", "Continue"),
        ("b", "break", "Break"),
        ("q", "quit", "Quit Debugger"),
        ("x", "quit_emulator", "Quit Emulator"),
        ("p", "jump_to_pc", "Jump to PC"),
    ]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
        # yield Controls()
        yield Status()

    def action_quit_emulator(self) -> None:
        try:
            emu.quit()
        except Exception as e:
            self.notify(f"Failed to quit emulator: {e}")

    def action_step(self) -> None:
        try:
            emu.step()
            self.query_one(Disassembly).scroll_to_pc_if_needed()
        except Exception as e:
            self.notify(f"Failed to step: {e}")


    def action_continue(self) -> None:
        try:
            emu.cont()
        except Exception as e:
            self.notify(f"Failed to continue: {e}")

    def action_break(self) -> None:
        try:
            emu.brk()
            self.query_one(Disassembly).scroll_to_pc_if_needed()
        except Exception as e:
            self.notify(f"Failed to break: {e}")

    def action_jump_to_pc(self) -> None:
        try:
            self.query_one(Disassembly).scroll_to_pc_if_needed()
        except Exception as e:
            self.notify(f"Failed to jump to PC: {e}")

if __name__ == "__main__":
    app = DebuggerApp()
    app.run()