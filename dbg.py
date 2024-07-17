#!/usr/bin/env python3
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Button, Label
from textual.reactive import reactive
from emulator_connector import EmulatorConnector

from capstone import *
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)

emu = EmulatorConnector(8123)

class Status(Static):
    def compose(self) -> ComposeResult:
        self.styles.layout = "horizontal"
        registers = emu.registers()
        registers_text = ""
        for key, value in registers.items():
            registers_text += f"{key}: {hex(value)}\n"
        yield Label(registers_text)

        disasm = ""
        for addr in range(registers["pc"] - (10 * 4), registers["pc"] + (10 * 4), 4):
            instr = int("0x" + emu.read_word(addr), 16)
            instr_bytes = instr.to_bytes(4, "big")
            for i in md.disasm(instr_bytes, addr & 0xFFFFFFFF):
                if addr == registers["pc"]:
                    disasm += "-> "
                else:
                    disasm += "   "

                disasm += f"{hex(addr & 0xFFFFFFFF)} {i.mnemonic} {i.op_str}\n"

        yield Label(disasm)

    def update(self) -> None:
        # self.registers = emu.registers()
        self.refresh(recompose=True)

    def on_mount(self) -> None:
        emu.register_on_update_handler(self.update)


class Controls(Static):
    def compose(self) -> ComposeResult:
        yield Button("Step", id="step", variant="success")
        yield Button("Continue", id="continue", variant="success")
        yield Button("Break", id="break", variant="error")


class DebuggerApp(App):
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

    def action_quit(self) -> None:
        exit(0)

    def action_quit_emulator(self) -> None:
        emu.quit()

    def action_step(self) -> None:
        emu.step()

    def action_continue(self) -> None:
        emu.cont()
        
    def action_break(self) -> None:
        emu.brk()

if __name__ == "__main__":
    app = DebuggerApp()
    app.run()