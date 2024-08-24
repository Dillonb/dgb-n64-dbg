#!/usr/bin/env python3
from textual.app import App, ComposeResult
from textual.widget import Widget
from textual.widgets import Header, Footer, Static, Button
from textual.reactive import reactive
from textual.events import Resize

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

class Disassembly(Widget):
    def __init__(self, request_update):
        super().__init__()
        self.request_update = request_update

    instructions = reactive([])
    pc: reactive[int] = reactive(0)
    height: reactive[int] = reactive(0)

    def on_mount(self) -> None:
        # self.height = int(self.styles.height.value)
        self.request_update()
        pass

    def on_resize(self, event: Resize):
        self.height = event.size.height
        self.request_update()
        pass

    def render(self) -> str:
        disasm = ""
        lines = 0
        for addr, instr_bytes in self.instructions:
            for i in md.disasm(instr_bytes, addr & 0xFFFFFFFF):
                if addr == self.pc:
                    disasm += "-> "
                else:
                    disasm += "   "

                disasm += f"{hex(addr & 0xFFFFFFFF)} {i.mnemonic} {i.op_str}\n"
                lines += 1

        return disasm

class Status(Static):
    def compose(self) -> ComposeResult:
        self.styles.layout = "horizontal"
        yield Registers()
        yield Disassembly(self.update_state)

    def update_state(self) -> None:
        try:
            registers = emu.registers()
            self.query_one(Registers).registers = registers
            self.query_one(Disassembly).pc = registers["pc"]

            instrs = []
            disasm_height = self.query_one(Disassembly).height
            instrs_before_after = int((disasm_height - 1) // 2)

            for addr in range(registers["pc"] - (instrs_before_after * 4), registers["pc"] + (instrs_before_after * 4), 4):
                instr = int("0x" + emu.read_word(addr), 16)
                instr_bytes = instr.to_bytes(4, "big")
                instrs.append((addr, instr_bytes))

            self.query_one(Disassembly).instructions = instrs
        except Exception as e:
            self.notify(f"Error updating state! {e}")

    def on_mount(self) -> None:
        emu.register_on_update_handler(self.update_state)


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
        ("x", "quit_emulator", "Quit Emulator")
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
        except Exception as e:
            self.notify(f"Failed to break: {e}")

if __name__ == "__main__":
    app = DebuggerApp()
    app.run()