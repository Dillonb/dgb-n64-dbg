#!/usr/bin/env python3
from rich.segment import Segment
from rich.style import Style
from rich.theme import Theme
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Grid, VerticalScroll, Horizontal
from textual.screen import Screen, ModalScreen
from textual.widget import Widget
from textual.scroll_view import ScrollView
from textual.geometry import Size
from textual.widgets import Header, Footer, Static, Button, Label, Input
from textual.reactive import reactive
from textual.events import Click, Key
from textual.strip import Strip

from emulator_connector import EmulatorConnector

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)

emu = EmulatorConnector(8123)

class Registers(Widget):
    gprs = [ "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
             "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra" ];
    hidden = { "zero" }

    registers: reactive[dict[str, int]] = reactive({})
    state: reactive[dict] = reactive({})

    def render(self) -> str:
        text = ""
        for name in self.gprs:
            if name in self.registers.keys():

                text += f"[gruv_green]{name}[/]: "
                if "running" in self.state and self.state["running"]:
                    text += "[i]Emulator running[/]\n"
                else:
                    text += f"{hex(self.registers[name])}\n"

        text += "\n\n"
        for key, value in self.registers.items():
            if key not in self.gprs and key not in self.hidden:
                text += f"[gruv_green]{key}[/]: "
                if "running" in self.state and self.state["running"]:
                    text += "[i]Emulator running[/]\n"
                else:
                    text += f"{hex(value)}\n"
        return text.strip()

class Disassembly(ScrollView):
    pc: reactive[int] = reactive(0)
    breakpoints: reactive[set[int]] = reactive(set())
    registers: reactive[dict[str, int]] = reactive({})
    state: reactive[dict] = reactive({})
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
        scroll_x, scroll_y = self.scroll_offset
        address = (y + scroll_y) << 2

        active = address == (self.pc & self.addr_mask) and ("running" in self.state and not self.state["running"])
        active_text = "active" if active else "inactive"

        line_style = self.get_component_rich_style(f"{active_text}-line").background_style

        address_style = Style.combine([self.get_component_rich_style(f"address"), line_style])
        iw_style = Style.combine([self.get_component_rich_style(f"instruction-word"), line_style])
        disasm_instr_style = Style.combine([self.get_component_rich_style(f"instruction-disasm-instr"), line_style])
        disasm_args_style = Style.combine([self.get_component_rich_style(f"instruction-disasm-args"), line_style])
        other_segment_style = Style.combine([self.get_component_rich_style(f"other-segment"), line_style])

        bp_text = self.no_bp
        if address in self.breakpoints:
            bp_text = self.bp

        arrow_text = "🠶" if active else " "

        segments = [Segment(f"{bp_text}{arrow_text} ", other_segment_style)]
        segments.append(Segment(("{:08X}" if self.mode == 32 else "{:016X}").format(address), address_style))
        segments.append(Segment("   ", other_segment_style))

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
            disasm_instr_text = ""
            disasm_args_text = ""

        segments.append(Segment(iw_text, iw_style))
        segments.append(Segment(disasm_instr_text, disasm_instr_style))
        segments.append(Segment(disasm_args_text.ljust(25), disasm_args_style))

        reg_values = []
        if "running" in self.state and not self.state["running"]:
            for reg in disasm_args_text.split(", "):
                for reg_name in self.registers.keys():
                    if f"${reg_name}" in reg:
                        reg_values.append(f"{reg_name} = {hex(self.registers[reg_name])}")


        segments.append(Segment(", ".join(reg_values), iw_style))
        width = sum([len(segment.text) for segment in segments])

        if width > self.virtual_size.width:
            self.virtual_size = self.virtual_size.with_width(width)

        return Strip(segments).crop(scroll_x)

class Status(Static):
    def compose(self) -> ComposeResult:
        self.styles.layout = "horizontal"
        yield Registers()
        yield Disassembly()

    def update_state(self) -> None:
        try:
            registers = emu.registers()
            breakpoints = emu.breakpoints()
            state = emu.state()

            addr_mask = self.query_one(Disassembly).addr_mask

            breakpoints_set = set()
            for breakpoint in breakpoints:
                breakpoints_set.add(breakpoint["address"] & addr_mask)

            self.query_one(Registers).registers = registers
            self.query_one(Registers).state = state
            self.query_one(Disassembly).registers = registers
            self.query_one(Disassembly).pc = registers["pc"]
            self.query_one(Disassembly).breakpoints = breakpoints_set
            self.query_one(Disassembly).state = state

        except Exception as e:
            self.notify(f"Error updating state! {e}")

    def on_mount(self) -> None:
        emu.register_on_update_handler(self.update_state)
        self.update_state()
        self.query_one(Disassembly).scroll_to_pc_if_needed()

class GoToAddressScreen(ModalScreen):
    def __init__(self, jump_to):
        super().__init__()
        self.jump_to = jump_to

    def compose(self) -> ComposeResult:
        yield Grid(
                Input(placeholder="Address", id="address_input", restrict=r"[a-fA-F0-9]{1,16}"),
                id = "goto_address_dialog"
                )

    @on(Input.Submitted)
    def jump(self, event: Input.Submitted):
        try:
            self.jump_to(int(event.value, 16))
            self.app.pop_screen()
        except Exception as e:
            self.notify(f"Error: {e}")


    def on_key(self, key: Key):
        if key.key == "escape":
            self.app.pop_screen()

class BreakpointLine(Horizontal):
    def __init__(self, address):
        super().__init__()
        self.address = address

    def compose(self) -> ComposeResult:
        yield Button("X", classes="delete_bp_button", variant="error", id=f"delete_bp_{hex(self.address)}")
        yield Label(" 0x{:016X}".format(self.address))

class BreakpointsScreen(ModalScreen):
    def compose(self) -> ComposeResult:
        breakpoint_lines = []
        for bp in emu.breakpoints():
            breakpoint_lines.append(BreakpointLine(bp["address"]))
        yield VerticalScroll(
                Input(placeholder="Add New", id="address_input", restrict=r"[a-fA-F0-9]{1,16}"),
                *breakpoint_lines,
                id = "breakpoints_dialog"
                )

    def on_button_pressed(self, pressed: Button.Pressed):
        if pressed.button.id is not None and pressed.button.id.startswith("delete_bp_"):
            addr = int(pressed.button.id[10:], 16)
            emu.clear_breakpoint(addr)
            self.refresh(recompose=True)

    @on(Input.Submitted)
    def on_input_submitted(self, event: Input.Submitted):
        emu.set_breakpoint(int(event.value, 16))
        self.refresh(recompose=True)

    def on_key(self, key: Key):
        if key.key == "escape":
            self.app.pop_screen()


class DebuggerApp(App):
    CSS_PATH = "dbg.tcss"
    BINDINGS = [
        ("s", "step", "Step"),
        ("c", "break_continue", "Continue/Break"),
        ("b", "breakpoints", "Breakpoints"),
        ("q", "quit", "Quit Debugger"),
        ("x", "quit_emulator", "Quit Emulator"),
        ("g", "go_to_address", "Go to Address"),
        ("p", "go_to_pc", "Go to PC"),
    ]
    def on_mount(self):
        # For use in rich text
        self.console.push_theme(
                Theme({
                        "gruv_red": "#fb4934",
                        "gruv_green": "#b8bb26"
                    })
                )


    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
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


    def action_break_continue(self) -> None:
        try:
            if emu.state()["running"]:
                emu.brk();
                self.query_one(Disassembly).scroll_to_address_if_needed(emu.registers()["pc"])
            else:
                emu.cont()
        except Exception as e:
            self.notify(f"Failed to break/continue: {e}")

    def action_breakpoints(self) -> None:
        self.push_screen(BreakpointsScreen())

    def action_go_to_address(self) -> None:
        self.push_screen(GoToAddressScreen(self.query_one(Disassembly).scroll_to_address_if_needed))

    def action_go_to_pc(self) -> None:
        try:
            self.query_one(Disassembly).scroll_to_pc_if_needed()
        except Exception as e:
            self.notify(f"Failed to go to PC: {e}")

def main():
    app = DebuggerApp()
    app.run()

if __name__ == "__main__":
    main()