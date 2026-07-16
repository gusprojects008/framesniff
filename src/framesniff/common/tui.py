from cli_core.files import new_file_path

def export_tui_to_txt(app, output_filename: str = None):
    out_path = str(new_file_path(fullpath=output_filename))
    snapshot_lines = []
    def extract_table(widget):
        try:
            headers = []
            if hasattr(widget, "columns"):
                for col in widget.columns:
                    if hasattr(col, "label"):
                        headers.append(str(col.label))
                    elif hasattr(col, "header"):
                        headers.append(str(col.header))
                    else:
                        headers.append(str(col))
            rows = []
            if hasattr(widget, "rows") and hasattr(widget, "get_row"):
                for row_key in widget.rows:
                    row_data = widget.get_row(row_key)
                    if row_data:
                        rows.append(" | ".join(str(cell) for cell in row_data))
            if headers or rows:
                return "\n".join([" | ".join(headers)] + rows)
        except Exception as e:
            return f"[ERROR extracting table: {e}]"
        return None

    def extract_widget_text(widget):
        if "DataTable" in str(widget.__class__):
            return extract_table(widget)
        if hasattr(widget, "value") and widget.value:
            return str(widget.value).strip()
        if hasattr(widget, "renderable") and widget.renderable:
            return str(widget.renderable).strip()
        if hasattr(widget, "_text") and widget._text:
            return str(widget._text).strip()
        if hasattr(widget, "render") and callable(widget.render):
            try:
                rendered = widget.render()
                if rendered:
                    return str(rendered).strip()
            except:
                pass
        return None
    try:
        app.refresh()
        app.refresh(layout=True)
    except Exception:
        pass
    try:
        for widget in app.walk_children():
            text = extract_widget_text(widget)
            if text:
                snapshot_lines.append(text)
    except Exception as e:
        snapshot_lines.append(f"[ERROR walking widgets: {e}]")
    if not snapshot_lines and hasattr(app, "console"):
        try:
            snapshot_lines.append(app.console.export_text(clear=False))
        except Exception:
            snapshot_lines.append("[ERROR exporting console buffer]")
    snapshot = "\n".join(snapshot_lines)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(snapshot)
        print(f"[SUCCESS] TUI content exported to: {out_path}")
        return out_path
    except Exception as e:
        print(f"[ERROR] Failed to write file: {e}")
        return None
