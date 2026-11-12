import os
import re
from pathlib import Path

from patcher.utils.atomic import atomic_replace
from patcher.utils.console import err, ok


_IDENT = rb"[A-Za-z_$][\w$]*"
_UPDATE_CHECK = re.compile(
    rb"let (?P<result>" + _IDENT + rb")=" + _IDENT + rb"\(await " + _IDENT
    + rb"\(" + _IDENT + rb"\(\{existingBinaryValid:(?P<valid>" + _IDENT
    + rb"),existingValidVersion:(?P<version>" + _IDENT + rb"),releaseBaseUrl:"
    + _IDENT + rb",retryOptions:" + _IDENT + rb",outputChannel:(?P<log>"
    + _IDENT + rb")\}\)\)\);if\((?P=result)\.unreachableFallback\)return "
    + _IDENT + rb'==null\|\|' + _IDENT
    + rb'\(\{cacheHit:!0,\s*downloadReason:"manifest_unreachable_fallback",cliVersion:'
    + rb'(?P=version),\.\.\.' + _IDENT + rb'\}\),(?P<binary>' + _IDENT + rb');'
)
_PIN_LOG = b"[INSTALL] Reusing local Antigravity Backend (AG patcher)."


def _pin_statement(match):
    return (b'if(%s&&%s){%s.appendLine("%s");return %s;}' % (
        match["valid"], match["version"], match["log"], _PIN_LOG, match["binary"],
    ))


def _set_pinning(content, enabled):
    matches = list(_UPDATE_CHECK.finditer(content))
    if not enabled and _PIN_LOG not in content:
        return content
    if len(matches) != 1:
        raise ValueError("Backend updater pattern is missing or ambiguous")

    match = matches[0]
    statement = _pin_statement(match)
    offset = match.start()
    # Проверка версии остаётся штатной. Выходим до запроса манифеста, если версия подходит.
    if content.count(_PIN_LOG) == 1 and content[:offset].endswith(statement):
        return content if enabled else content[:offset - len(statement)] + content[offset:]
    if _PIN_LOG in content:
        raise ValueError("Existing backend pin could not be verified")
    return content[:offset] + statement + content[offset:]


def set_backend_pinning(main_js_path, enabled):
    """Закрепляет рабочий локальный бэкенд во встроенном расширении Windows IDE."""
    app_dir = Path(main_js_path).parent
    if app_dir.name.lower() == "out":
        app_dir = app_dir.parent
    extension_dir = app_dir / "extensions" / "agy"
    if not extension_dir.is_dir():
        return True  # В старых версиях IDE встроенного расширения agy нет.

    path = extension_dir / "vscode" / "extension.js"
    try:
        with path.open("rb") as source:
            content = source.read()
            source_stat = os.fstat(source.fileno())
        updated = _set_pinning(content, enabled)
        if updated != content:
            atomic_replace(path, updated, expected_stat=source_stat)
    except (OSError, ValueError) as exc:
        err(f"Could not {'pin' if enabled else 'unpin'} the IDE backend in {path}: {exc}")
        return False

    if enabled:
        ok("IDE will reuse the local backend when its version is compatible.")
    elif updated != content:
        ok("IDE backend automatic updates restored.")
    return True
