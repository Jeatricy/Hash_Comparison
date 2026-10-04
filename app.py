"""哈希值对比工具的 Tkinter 桌面界面。"""

from __future__ import annotations

import csv
import queue
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from hash_compare import (
    ComparisonCancelled,
    ComparisonResult,
    Difference,
    ScanResult,
    compare_results,
    human_size,
    scan_path,
)


ALGORITHMS = {
    "SHA-256（推荐）": "sha256",
    "SHA-512": "sha512",
    "SHA-1": "sha1",
    "MD5": "md5",
}


class HashCompareApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("哈希值对比工具")
        self.geometry("1120x760")
        self.minsize(900, 620)
        self.configure(bg="#f4f6f8")

        self.path_left = tk.StringVar()
        self.path_right = tk.StringVar()
        self.algorithm_label = tk.StringVar(value="SHA-256（推荐）")
        self.status_text = tk.StringVar(value="请选择两个文件或两个文件夹")
        self.summary_text = tk.StringVar(value="尚未比较")
        self.only_differences = tk.BooleanVar(value=True)
        self.progress_value = tk.DoubleVar(value=0)

        self._messages: queue.Queue[tuple] = queue.Queue()
        self._cancel_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._left_result: ScanResult | None = None
        self._right_result: ScanResult | None = None
        self._comparison: ComparisonResult | None = None

        self._configure_styles()
        self._build_ui()
        self.after(100, self._poll_messages)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("App.TFrame", background="#f4f6f8")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Title.TLabel", background="#f4f6f8", foreground="#17212b", font=("Microsoft YaHei UI", 19, "bold"))
        style.configure("Subtitle.TLabel", background="#f4f6f8", foreground="#607080", font=("Microsoft YaHei UI", 9))
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#243447", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("CardText.TLabel", background="#ffffff", foreground="#52606d", font=("Microsoft YaHei UI", 9))
        style.configure("Result.TLabel", background="#ffffff", foreground="#243447", font=("Microsoft YaHei UI", 13, "bold"))
        style.configure("Equal.Result.TLabel", background="#ffffff", foreground="#14804a", font=("Microsoft YaHei UI", 13, "bold"))
        style.configure("Diff.Result.TLabel", background="#ffffff", foreground="#c44b18", font=("Microsoft YaHei UI", 13, "bold"))
        style.configure("Error.Result.TLabel", background="#ffffff", foreground="#b42318", font=("Microsoft YaHei UI", 13, "bold"))
        style.configure("Accent.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=(18, 8))
        style.configure("Treeview", rowheight=27, font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, style="App.TFrame", padding=(24, 18))
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="哈希值对比工具", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="校验本地文件、映射网络驱动器或 SMB/UNC 路径；文件夹会递归比较路径、空目录与文件内容。",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 14))

        select_card = ttk.Frame(outer, style="Card.TFrame", padding=16)
        select_card.pack(fill="x")
        select_card.columnconfigure(1, weight=1)
        self._path_row(select_card, 0, "来源 A", self.path_left)
        self._path_row(select_card, 1, "来源 B", self.path_right)

        action_row = ttk.Frame(select_card, style="Card.TFrame")
        action_row.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(13, 0))
        ttk.Label(action_row, text="哈希算法", style="CardText.TLabel").pack(side="left")
        self.algorithm_box = ttk.Combobox(
            action_row, textvariable=self.algorithm_label, values=list(ALGORITHMS),
            state="readonly", width=18,
        )
        self.algorithm_box.pack(side="left", padx=(8, 14))
        ttk.Button(action_row, text="交换 A / B", command=self._swap_paths).pack(side="left")
        self.cancel_button = ttk.Button(action_row, text="取消", command=self._cancel, state="disabled")
        self.cancel_button.pack(side="right", padx=(8, 0))
        self.compare_button = ttk.Button(action_row, text="开始比较", style="Accent.TButton", command=self._start_compare)
        self.compare_button.pack(side="right")

        progress_card = ttk.Frame(outer, style="Card.TFrame", padding=(16, 12))
        progress_card.pack(fill="x", pady=(12, 0))
        self.progress = ttk.Progressbar(progress_card, variable=self.progress_value, maximum=100)
        self.progress.pack(fill="x")
        ttk.Label(progress_card, textvariable=self.status_text, style="CardText.TLabel").pack(anchor="w", pady=(6, 0))

        result_card = ttk.Frame(outer, style="Card.TFrame", padding=16)
        result_card.pack(fill="both", expand=True, pady=(12, 0))
        result_header = ttk.Frame(result_card, style="Card.TFrame")
        result_header.pack(fill="x")
        self.result_label = ttk.Label(result_header, textvariable=self.summary_text, style="Result.TLabel")
        self.result_label.pack(side="left")
        self.export_button = ttk.Button(result_header, text="导出 CSV 报告", command=self._export_csv, state="disabled")
        self.export_button.pack(side="right")
        ttk.Checkbutton(
            result_header, text="只看差异", variable=self.only_differences,
            command=self._render_rows,
        ).pack(side="right", padx=14)

        self.digest_text = tk.Text(
            result_card, height=4, wrap="none", relief="flat", bg="#f7f9fb", fg="#344054",
            font=("Consolas", 9), padx=8, pady=6, state="disabled",
        )
        self.digest_text.pack(fill="x", pady=(10, 10))

        tree_frame = ttk.Frame(result_card, style="Card.TFrame")
        tree_frame.pack(fill="both", expand=True)
        columns = ("status", "path", "size_left", "size_right", "hash_left", "hash_right", "detail")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        headings = {
            "status": "状态", "path": "相对路径", "size_left": "A 大小", "size_right": "B 大小",
            "hash_left": "A 哈希", "hash_right": "B 哈希", "detail": "说明",
        }
        widths = {"status": 85, "path": 260, "size_left": 90, "size_right": 90, "hash_left": 235, "hash_right": 235, "detail": 220}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], minwidth=60, stretch=column in {"path", "detail"})
        self.tree.tag_configure("different", foreground="#b54708")
        self.tree.tag_configure("error", foreground="#b42318")
        self.tree.tag_configure("same", foreground="#52606d")
        y_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

    def _path_row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label, style="CardTitle.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=5)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text="选文件", command=lambda: self._choose_file(variable)).grid(row=row, column=2, padx=(8, 4), pady=5)
        ttk.Button(parent, text="选文件夹", command=lambda: self._choose_directory(variable)).grid(row=row, column=3, padx=4, pady=5)
        ttk.Button(parent, text="清空", command=lambda: variable.set("")).grid(row=row, column=4, padx=(4, 0), pady=5)

    @staticmethod
    def _initial_directory(value: str) -> str | None:
        if not value:
            return None
        path = Path(value)
        if path.is_dir():
            return str(path)
        if path.parent.is_dir():
            return str(path.parent)
        return None

    def _choose_file(self, variable: tk.StringVar) -> None:
        selected = filedialog.askopenfilename(title="选择要比较的文件", initialdir=self._initial_directory(variable.get()))
        if selected:
            variable.set(selected)

    def _choose_directory(self, variable: tk.StringVar) -> None:
        selected = filedialog.askdirectory(title="选择要比较的文件夹", initialdir=self._initial_directory(variable.get()), mustexist=True)
        if selected:
            variable.set(selected)

    def _swap_paths(self) -> None:
        left, right = self.path_left.get(), self.path_right.get()
        self.path_left.set(right)
        self.path_right.set(left)

    def _set_busy(self, busy: bool) -> None:
        self.compare_button.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy else "disabled")
        self.algorithm_box.configure(state="disabled" if busy else "readonly")

    def _start_compare(self) -> None:
        left = self.path_left.get().strip().strip('"')
        right = self.path_right.get().strip().strip('"')
        if not left or not right:
            messagebox.showwarning("缺少路径", "请先选择或输入来源 A 和来源 B。")
            return
        if self._worker is not None and self._worker.is_alive():
            return

        self.path_left.set(left)
        self.path_right.set(right)
        self._cancel_event.clear()
        self._comparison = None
        self._left_result = None
        self._right_result = None
        self.tree.delete(*self.tree.get_children())
        self._set_digest_text("")
        self.summary_text.set("正在比较…")
        self.result_label.configure(style="Result.TLabel")
        self.status_text.set("正在连接并检查来源 A…")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.export_button.configure(state="disabled")
        self._set_busy(True)

        algorithm = ALGORITHMS[self.algorithm_label.get()]
        self._worker = threading.Thread(
            target=self._compare_worker, args=(left, right, algorithm), daemon=True,
        )
        self._worker.start()

    def _compare_worker(self, left: str, right: str, algorithm: str) -> None:
        last_report = 0.0

        def make_progress(side: str):
            def report(phase: str, current: str, done: int, total: int) -> None:
                nonlocal last_report
                now = time.monotonic()
                if phase in {"scan", "done"} or now - last_report >= 0.08:
                    last_report = now
                    self._messages.put(("progress", side, phase, current, done, total))
            return report

        try:
            result_left = scan_path(left, algorithm, self._cancel_event, make_progress("A"))
            result_right = scan_path(right, algorithm, self._cancel_event, make_progress("B"))
            comparison = compare_results(result_left, result_right)
            self._messages.put(("result", result_left, result_right, comparison))
        except ComparisonCancelled:
            self._messages.put(("cancelled",))
        except Exception as exc:
            self._messages.put(("error", str(exc)))

    def _poll_messages(self) -> None:
        try:
            while True:
                message = self._messages.get_nowait()
                kind = message[0]
                if kind == "progress":
                    self._handle_progress(*message[1:])
                elif kind == "result":
                    self._show_result(*message[1:])
                elif kind == "cancelled":
                    self._finish_work("已取消", "比较已取消")
                elif kind == "error":
                    self._finish_work("比较失败", "发生错误")
                    self.result_label.configure(style="Error.Result.TLabel")
                    messagebox.showerror("比较失败", message[1])
        except queue.Empty:
            pass
        self.after(100, self._poll_messages)

    def _handle_progress(self, side: str, phase: str, current: str, done: int, total: int) -> None:
        if phase == "scan":
            self.progress.stop()
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            self.status_text.set(f"来源 {side}：正在扫描 {current}")
            return
        self.progress.stop()
        self.progress.configure(mode="determinate")
        percent = 100 if total == 0 and phase == "done" else (done / total * 100 if total else 0)
        self.progress_value.set(min(percent, 100))
        if phase == "done":
            self.status_text.set(f"来源 {side}：扫描完成")
        else:
            self.status_text.set(f"来源 {side}：{current}  ({human_size(done)} / {human_size(total)})")

    def _show_result(self, left: ScanResult, right: ScanResult, comparison: ComparisonResult) -> None:
        self._left_result = left
        self._right_result = right
        self._comparison = comparison
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress_value.set(100)
        self._set_busy(False)
        self.export_button.configure(state="normal")
        self.summary_text.set(comparison.summary)
        if not comparison.conclusive:
            style = "Error.Result.TLabel"
        else:
            style = "Equal.Result.TLabel" if comparison.equal else "Diff.Result.TLabel"
        self.result_label.configure(style=style)
        self.status_text.set("比较完成")

        algorithm = left.algorithm.upper().replace("SHA256", "SHA-256").replace("SHA512", "SHA-512").replace("SHA1", "SHA-1")
        if left.kind == "directory":
            left_meta = f"{left.file_count} 个文件，{left.directory_count} 个子目录，{human_size(left.total_size)}"
            right_meta = f"{right.file_count} 个文件，{right.directory_count} 个子目录，{human_size(right.total_size)}"
        else:
            left_meta = human_size(left.total_size)
            right_meta = human_size(right.total_size)
        digest_info = (
            f"A  [{left_meta}]\n{algorithm}: {left.digest}\n"
            f"B  [{right_meta}]\n{algorithm}: {right.digest}"
        )
        self._set_digest_text(digest_info)
        self._render_rows()

    def _finish_work(self, summary: str, status: str) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress_value.set(0)
        self.summary_text.set(summary)
        self.status_text.set(status)
        self._set_busy(False)

    def _render_rows(self) -> None:
        self.tree.delete(*self.tree.get_children())
        if self._comparison is None:
            return
        rows = self._comparison.differences if self.only_differences.get() else self._comparison.all_rows
        for row in rows:
            left = row.left
            right = row.right
            tag = "same" if row.status == "一致" else ("error" if row.status == "读取失败" else "different")
            self.tree.insert("", "end", values=(
                row.status,
                row.relative_path,
                self._entry_size(left),
                self._entry_size(right),
                left.digest if left else "",
                right.digest if right else "",
                row.detail,
            ), tags=(tag,))

    @staticmethod
    def _entry_size(entry) -> str:
        if entry is None or entry.kind == "dir":
            return ""
        return human_size(entry.size)

    def _set_digest_text(self, value: str) -> None:
        self.digest_text.configure(state="normal")
        self.digest_text.delete("1.0", "end")
        self.digest_text.insert("1.0", value)
        self.digest_text.configure(state="disabled")

    def _cancel(self) -> None:
        self._cancel_event.set()
        self.status_text.set("正在取消…")
        self.cancel_button.configure(state="disabled")

    def _export_csv(self) -> None:
        if not self._comparison or not self._left_result or not self._right_result:
            return
        selected = filedialog.asksaveasfilename(
            title="导出比较报告", defaultextension=".csv",
            filetypes=(("CSV 文件", "*.csv"), ("所有文件", "*.*")),
            initialfile="哈希对比报告.csv",
        )
        if not selected:
            return
        try:
            with open(selected, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.writer(stream)
                writer.writerow(["结论", self._comparison.summary])
                writer.writerow(["来源 A", str(self._left_result.path)])
                writer.writerow(["来源 B", str(self._right_result.path)])
                writer.writerow(["算法", self._left_result.algorithm])
                writer.writerow(["A 总哈希", self._left_result.digest])
                writer.writerow(["B 总哈希", self._right_result.digest])
                writer.writerow([])
                writer.writerow(["状态", "相对路径", "A 大小(字节)", "B 大小(字节)", "A 哈希", "B 哈希", "说明"])
                for row in self._comparison.all_rows:
                    writer.writerow([
                        row.status, row.relative_path,
                        "" if row.left is None else row.left.size,
                        "" if row.right is None else row.right.size,
                        "" if row.left is None else row.left.digest,
                        "" if row.right is None else row.right.digest,
                        row.detail,
                    ])
            messagebox.showinfo("导出成功", f"报告已保存到：\n{selected}")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    def _on_close(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            if not messagebox.askyesno("任务仍在运行", "哈希计算尚未完成，确定要退出吗？"):
                return
            self._cancel_event.set()
        self.destroy()


def main() -> None:
    try:
        HashCompareApp().mainloop()
    except Exception:
        details = traceback.format_exc()
        log_path = Path(__file__).with_name("启动错误.log")
        try:
            log_path.write_text(details, encoding="utf-8")
        except OSError:
            pass
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                f"程序启动失败，详细信息已写入：\n{log_path}\n\n{details[-1200:]}",
                "哈希值对比工具 - 启动失败",
                0x10,
            )
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
