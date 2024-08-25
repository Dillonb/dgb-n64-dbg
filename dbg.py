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
    registers: reactive[dict[str, int]] = reactive({})

    def render(self) -> str:
        text = ""
        for key, value in self.registers.items():
            text += f"{key}: {hex(value)}\n"
        return text

class Disassembly(ScrollView):
    pc: reactive[int] = reactive(0)
    mode: int
    addr_mask: int

    bp = "🔴"
    muted_bp = "⭕"

    COMPONENT_CLASSES = {
        "address",
        "instruction-word",
        "instruction-disasm",
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
        if click.x <= 8: # Only if you click on the address
            self.notify(f"{hex(address)} {click.x}")

    def render_line(self, y: int) -> Strip:
        _, scroll_y = self.scroll_offset
        address = (y + scroll_y) << 2

        address_style = self.get_component_rich_style("address")
        iw_style = self.get_component_rich_style("instruction-word")
        disasm_style = self.get_component_rich_style("instruction-disasm")

        segments = [Segment(("{:08X}" if self.mode == 32 else "{:016X}").format(address), address_style)]
        segments.append(Segment(" -> " if address == (self.pc & self.addr_mask) else "    "))

        try:
            instr = int("0x" + emu.read_word(address), 16)
            instr_bytes = instr.to_bytes(4, "big")
            disasm = []
            for i in md.disasm(instr_bytes, address & self.addr_mask):
                disasm.append(f"{i.mnemonic} {i.op_str}")

            segments.append(Segment("{:08X}".format(instr), iw_style))
            if len(disasm) != 1:
                segments.append(Segment(f"ERROR: len = {len(disasm)}"))
            else:
                segments.append(Segment("\t" + disasm[0], disasm_style))
        except Exception:
            segments.append(Segment("ERROR"))

        return Strip(segments)

class Status(Static):
    def compose(self) -> ComposeResult:
        self.styles.layout = "horizontal"
        yield Registers()
        yield Disassembly()

    def update_state(self) -> None:
        try:
            registers = emu.registers()
            self.query_one(Registers).registers = registers
            self.query_one(Disassembly).pc = registers["pc"]

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
        ("d", "toggle_dark", "Toggle dark mode"),
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

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark

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