import html
import pathlib
import re
import sys


def convert_inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r'<img alt="\1" src="\2" />', text)
    return text


def markdown_to_html(md_text: str, title: str) -> str:
    lines = md_text.splitlines()
    parts = [
        "<!doctype html>",
        "<html lang='zh-CN'>",
        "<head>",
        "  <meta charset='utf-8' />",
        f"  <title>{html.escape(title)}</title>",
        "  <style>",
        "    html, body { background: #ffffff; }",
        "    body { font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif; margin: 40px auto; max-width: 920px; color: #1f2937; line-height: 1.7; }",
        "    h1, h2, h3 { color: #0f172a; }",
        "    h1 { font-size: 30px; border-bottom: 2px solid #cbd5e1; padding-bottom: 8px; }",
        "    h2 { font-size: 22px; margin-top: 28px; }",
        "    h3 { font-size: 18px; margin-top: 18px; }",
        "    p, li { font-size: 14px; }",
        "    ul { padding-left: 24px; }",
        "    pre { background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 8px; overflow-x: auto; }",
        "    code { font-family: 'SFMono-Regular', 'Menlo', monospace; background: #e2e8f0; padding: 1px 4px; border-radius: 4px; }",
        "    pre code { background: transparent; padding: 0; }",
        "    img { max-width: 100%; margin: 12px 0; border: 1px solid #cbd5e1; border-radius: 8px; }",
        "  </style>",
        "</head>",
        "<body>",
    ]

    in_list = False
    in_code = False
    paragraph = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            parts.append(f"<p>{convert_inline(' '.join(paragraph))}</p>")
            paragraph = []

    for line in lines:
        stripped = line.rstrip()
        if stripped.startswith("```"):
            flush_paragraph()
            if in_list:
                parts.append("</ul>")
                in_list = False
            if not in_code:
                parts.append("<pre><code>")
                in_code = True
            else:
                parts.append("</code></pre>")
                in_code = False
            continue

        if in_code:
            parts.append(html.escape(line))
            continue

        if not stripped:
            flush_paragraph()
            if in_list:
                parts.append("</ul>")
                in_list = False
            continue

        if stripped.startswith("# "):
            flush_paragraph()
            if in_list:
                parts.append("</ul>")
                in_list = False
            parts.append(f"<h1>{convert_inline(stripped[2:])}</h1>")
            continue

        if stripped.startswith("## "):
            flush_paragraph()
            if in_list:
                parts.append("</ul>")
                in_list = False
            parts.append(f"<h2>{convert_inline(stripped[3:])}</h2>")
            continue

        if stripped.startswith("### "):
            flush_paragraph()
            if in_list:
                parts.append("</ul>")
                in_list = False
            parts.append(f"<h3>{convert_inline(stripped[4:])}</h3>")
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            if not in_list:
                parts.append("<ul>")
                in_list = True
            parts.append(f"<li>{convert_inline(stripped[2:])}</li>")
            continue

        paragraph.append(stripped)

    flush_paragraph()
    if in_list:
        parts.append("</ul>")
    if in_code:
        parts.append("</code></pre>")

    parts.extend(["</body>", "</html>"])
    return "\n".join(parts)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: md_to_html.py INPUT.md OUTPUT.html", file=sys.stderr)
        return 2

    input_path = pathlib.Path(sys.argv[1])
    output_path = pathlib.Path(sys.argv[2])
    md_text = input_path.read_text(encoding="utf-8")
    html_text = markdown_to_html(md_text, input_path.stem)
    output_path.write_text(html_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
