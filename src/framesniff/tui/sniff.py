from pktparsers.tui.screens.packet_editor import PacketEditorScreen
from textual.widgets import Button

send_btn = Button("Send Raw", id="btn-send-raw")
screen = PacketEditorScreen(parsed, raw, extra_actions=[send_btn])
app.push_screen(screen)

# framesniff escuta o evento do seu próprio botão normalmente:
def on_button_pressed(self, event: Button.Pressed):
    if event.button.id == "btn-send-raw":
        raw_bytes = build_from_parsed(self._edited_parsed)
        self.send_raw(raw_bytes)
