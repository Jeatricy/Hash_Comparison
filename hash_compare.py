"""文件与文件夹哈希计算、对比逻辑。

本模块不依赖 UI，便于单元测试或被其他脚本复用。
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Callable, Dict, Iterable, Optional


CHUNK_SIZE = 4 * 1024 * 1024
ProgressCallback = Callable[[str, str, int, int], None]


class ComparisonCancelled(Exception):
    """用户取消了计算。"""


@dataclass(frozen=True)
class EntryInfo:
    kind: str
    size: int = 0
    digest: str = ""
    error: str = ""


@dataclass
class ScanResult:
    path: Path
    kind: str
    algorithm: str
    digest: str = ""
    entries: Dict[str, EntryInfo] = field(default_factory=dict)
    total_size: int = 0
    file_count: int = 0
    directory_count: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Difference:
    status: str
    relative_path: str
    left: Optional[EntryInfo]
    right: Optional[EntryInfo]
    detail: str


@dataclass
class ComparisonResult:
    equal: bool
    conclusive: bool
    summary: str
    differences: list[Difference]
    all_rows: list[Difference]


def _check_cancel(cancel_event: Optional[Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ComparisonCancelled()


def _new_hasher(algorithm: str):
    try:
        return hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"不支持的哈希算法：{algorithm}") from exc


def _hash_file(
    path: Path,
    algorithm: str,
    cancel_event: Optional[Event],
    on_chunk: Optional[Callable[[int], None]] = None,
) -> str:
    hasher = _new_hasher(algorithm)
    with path.open("rb") as stream:
        while True:
            _check_cancel(cancel_event)
            block = stream.read(CHUNK_SIZE)
            if not block:
                break
            hasher.update(block)
            if on_chunk is not None:
                on_chunk(len(block))
    return hasher.hexdigest()


def _iter_directory(
    root: Path, cancel_event: Optional[Event]
) -> Iterable[tuple[str, Path, str, int, str]]:
    """返回 (相对路径, 绝对路径, 类型, 大小, 预扫描错误)。"""
    pending = [root]
    while pending:
        _check_cancel(cancel_event)
        current = pending.pop()
        try:
            with os.scandir(current) as iterator:
                children = sorted(iterator, key=lambda item: item.name, reverse=True)
        except OSError as exc:
            relative = current.relative_to(root).as_posix() or "."
            yield relative, current, "error", 0, str(exc)
            continue

        for item in children:
            _check_cancel(cancel_event)
            full_path = Path(item.path)
            relative = full_path.relative_to(root).as_posix()
            try:
                if item.is_symlink():
                    target = os.readlink(full_path)
                    yield relative, full_path, "link", len(target.encode("utf-8")), target
                elif item.is_dir(follow_symlinks=False):
                    yield relative, full_path, "dir", 0, ""
                    pending.append(full_path)
                elif item.is_file(follow_symlinks=False):
                    size = item.stat(follow_symlinks=False).st_size
                    yield relative, full_path, "file", size, ""
                else:
                    yield relative, full_path, "other", 0, "不支持的文件类型"
            except OSError as exc:
                yield relative, full_path, "error", 0, str(exc)


def _folder_digest(entries: Dict[str, EntryInfo], algorithm: str) -> str:
    """将目录结构、路径、大小和内容哈希合成为确定性的文件夹哈希。"""
    hasher = _new_hasher(algorithm)
    for relative_path in sorted(entries):
        entry = entries[relative_path]
        fields = (
            entry.kind.encode("utf-8"),
            relative_path.encode("utf-8"),
            str(entry.size).encode("ascii"),
            entry.digest.encode("ascii"),
            entry.error.encode("utf-8"),
        )
        for field_value in fields:
            hasher.update(len(field_value).to_bytes(8, "big"))
            hasher.update(field_value)
    return hasher.hexdigest()


def scan_path(
    raw_path: str | os.PathLike[str],
    algorithm: str = "sha256",
    cancel_event: Optional[Event] = None,
    progress: Optional[ProgressCallback] = None,
) -> ScanResult:
    """扫描并计算一个文件或目录的哈希清单。"""
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"路径不存在或当前账号无权访问：{path}")

    _check_cancel(cancel_event)
    if path.is_file():
        size = path.stat().st_size
        done = 0

        def report_chunk(length: int) -> None:
            nonlocal done
            done += length
            if progress is not None:
                progress("hash", path.name, done, size)

        if progress is not None:
            progress("scan", path.name, 0, size)
        digest = _hash_file(path, algorithm, cancel_event, report_chunk)
        entry = EntryInfo("file", size, digest)
        return ScanResult(
            path=path,
            kind="file",
            algorithm=algorithm,
            digest=digest,
            entries={path.name: entry},
            total_size=size,
            file_count=1,
        )

    if not path.is_dir():
        raise ValueError(f"只支持普通文件或文件夹：{path}")

    if progress is not None:
        progress("scan", "正在读取目录结构…", 0, 0)

    discovered = list(_iter_directory(path, cancel_event))
    total_size = sum(size for _, _, kind, size, _ in discovered if kind == "file")
    result = ScanResult(path=path, kind="directory", algorithm=algorithm)
    result.total_size = total_size
    processed_bytes = 0

    for relative, full_path, kind, expected_size, note in discovered:
        _check_cancel(cancel_event)
        if kind == "dir":
            result.entries[relative] = EntryInfo("dir")
            result.directory_count += 1
            continue
        if kind == "link":
            link_digest = hashlib.new(algorithm, note.encode("utf-8")).hexdigest()
            result.entries[relative] = EntryInfo("link", expected_size, link_digest)
            continue
        if kind in {"error", "other"}:
            message = f"{relative}: {note}"
            result.entries[relative] = EntryInfo(kind, error=note)
            result.errors.append(message)
            continue

        def report_chunk(length: int, current: str = relative) -> None:
            nonlocal processed_bytes
            processed_bytes += length
            if progress is not None:
                progress("hash", current, processed_bytes, total_size)

        try:
            before = full_path.stat()
            digest = _hash_file(full_path, algorithm, cancel_event, report_chunk)
            after = full_path.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise OSError("读取期间文件发生了变化，请重新比较")
            result.entries[relative] = EntryInfo("file", after.st_size, digest)
            result.file_count += 1
        except OSError as exc:
            message = f"{relative}: {exc}"
            result.entries[relative] = EntryInfo("error", expected_size, error=str(exc))
            result.errors.append(message)

    result.digest = _folder_digest(result.entries, algorithm)
    if progress is not None:
        progress("done", "扫描完成", total_size, total_size)
    return result


def compare_results(left: ScanResult, right: ScanResult) -> ComparisonResult:
    if left.kind != right.kind:
        row = Difference("类型不同", "(根路径)", None, None, "一侧是文件，另一侧是文件夹")
        return ComparisonResult(False, True, row.detail, [row], [row])

    if left.kind == "file":
        left_entry = next(iter(left.entries.values()))
        right_entry = next(iter(right.entries.values()))
        equal = left_entry.size == right_entry.size and left_entry.digest == right_entry.digest
        detail = "内容完全一致" if equal else "文件内容不同"
        status = "一致" if equal else "内容不同"
        row = Difference(status, "(所选文件)", left_entry, right_entry, detail)
        return ComparisonResult(equal, True, detail, [] if equal else [row], [row])

    keys = sorted(set(left.entries) | set(right.entries))
    rows: list[Difference] = []
    has_error = bool(left.errors or right.errors)
    for relative in keys:
        item_left = left.entries.get(relative)
        item_right = right.entries.get(relative)
        if item_left is None:
            row = Difference("仅右侧", relative, None, item_right, "左侧缺少此项")
        elif item_right is None:
            row = Difference("仅左侧", relative, item_left, None, "右侧缺少此项")
        elif item_left.error or item_right.error:
            has_error = True
            detail = f"左：{item_left.error or '正常'}；右：{item_right.error or '正常'}"
            row = Difference("读取失败", relative, item_left, item_right, detail)
        elif item_left.kind != item_right.kind:
            row = Difference(
                "类型不同", relative, item_left, item_right,
                f"左侧 {item_left.kind}，右侧 {item_right.kind}",
            )
        elif item_left.size != item_right.size:
            row = Difference("大小不同", relative, item_left, item_right, "文件大小不同")
        elif item_left.digest != item_right.digest:
            row = Difference("内容不同", relative, item_left, item_right, "哈希值不同")
        else:
            row = Difference("一致", relative, item_left, item_right, "一致")
        rows.append(row)

    differences = [row for row in rows if row.status != "一致"]
    if has_error:
        return ComparisonResult(
            False, False, f"有 {len(left.errors) + len(right.errors)} 项读取失败，无法得出完整结论",
            differences, rows,
        )
    equal = not differences and left.digest == right.digest
    summary = "文件夹内容完全一致" if equal else f"发现 {len(differences)} 项差异"
    return ComparisonResult(equal, True, summary, differences, rows)


def human_size(size: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"
