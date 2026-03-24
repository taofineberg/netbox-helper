#!/usr/bin/env python3
"""Export a Netbox-import CSV using source-table value mapping.

Given a target Netbox-Config!D7 site value, this script:
1) Resolves source rows from the customer sheet referenced by Netbox-Config!B2.
2) Builds old->new replacements from source row differences.
3) Applies replacements to an existing Netbox-import template CSV.
4) Saves output as <G7>.csv where G7 is Facility-Code for the target site.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
D4_ALLOWED_VALUES = ("1", "2", "3", "4")


@dataclass
class Cell:
    row: int
    col: int
    value: str


def col_ref_to_index(cell_ref: str) -> int:
    letters = "".join(ch for ch in cell_ref if ch.isalpha())
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch.upper()) - ord("A") + 1)
    return n - 1


def cell_name_to_pos(cell_name: str) -> tuple[int, int]:
    match = re.fullmatch(r"([A-Za-z]+)(\d+)", cell_name)
    if not match:
        raise ValueError(f"Invalid cell name: {cell_name}")
    col_s, row_s = match.groups()
    col = 0
    for ch in col_s.upper():
        col = col * 26 + (ord(ch) - ord("A") + 1)
    return int(row_s), col - 1


class XlsxReader:
    def __init__(self, xlsx_path: Path) -> None:
        self.xlsx_path = xlsx_path
        self.zf = ZipFile(xlsx_path)
        self.shared_strings = self._load_shared_strings()
        self.sheet_paths = self._load_sheet_paths()

    def close(self) -> None:
        self.zf.close()

    def _load_shared_strings(self) -> list[str]:
        if "xl/sharedStrings.xml" not in self.zf.namelist():
            return []
        sst = ET.fromstring(self.zf.read("xl/sharedStrings.xml"))
        values: list[str] = []
        for si in sst.findall(f"{{{NS_MAIN}}}si"):
            values.append("".join((t.text or "") for t in si.iter(f"{{{NS_MAIN}}}t")))
        return values

    def _load_sheet_paths(self) -> dict[str, str]:
        wb = ET.fromstring(self.zf.read("xl/workbook.xml"))
        rels = ET.fromstring(self.zf.read("xl/_rels/workbook.xml.rels"))
        rel_map = {r.attrib["Id"]: r.attrib["Target"] for r in rels}

        result: dict[str, str] = {}
        for sheet in wb.findall(f"{{{NS_MAIN}}}sheets/{{{NS_MAIN}}}sheet"):
            name = sheet.attrib.get("name")
            rid = sheet.attrib.get(f"{{{NS_REL}}}id")
            if not name or not rid:
                continue
            target = rel_map[rid]
            result[name] = target if target.startswith("xl/") else f"xl/{target}"
        return result

    def parse_sheet_cells(self, sheet_name: str) -> dict[tuple[int, int], Cell]:
        if sheet_name not in self.sheet_paths:
            raise KeyError(f'Sheet "{sheet_name}" not found')
        ws = ET.fromstring(self.zf.read(self.sheet_paths[sheet_name]))
        cells: dict[tuple[int, int], Cell] = {}

        for row in ws.findall(f".//{{{NS_MAIN}}}row"):
            row_num = int(row.attrib.get("r", "0"))
            for c in row.findall(f"{{{NS_MAIN}}}c"):
                ref = c.attrib.get("r", "")
                col_idx = col_ref_to_index(ref) if ref else 0
                ctype = c.attrib.get("t", "")
                value = ""

                if ctype == "inlineStr":
                    is_elem = c.find(f"{{{NS_MAIN}}}is")
                    if is_elem is not None:
                        value = "".join((t.text or "") for t in is_elem.iter(f"{{{NS_MAIN}}}t"))
                else:
                    v = c.find(f"{{{NS_MAIN}}}v")
                    if v is not None and v.text is not None:
                        raw = v.text
                        if ctype == "s" and raw.isdigit():
                            idx = int(raw)
                            value = self.shared_strings[idx] if idx < len(self.shared_strings) else raw
                        else:
                            value = raw

                cells[(row_num, col_idx)] = Cell(row=row_num, col=col_idx, value=value)
        return cells


def get_cell(cells: dict[tuple[int, int], Cell], cell_name: str) -> str:
    row, col = cell_name_to_pos(cell_name)
    cell = cells.get((row, col))
    return cell.value if cell else ""


def build_sheet_matrix(cells: dict[tuple[int, int], Cell]) -> list[list[str]]:
    if not cells:
        return []
    max_row = max(r for r, _ in cells.keys())
    max_col = max(c for _, c in cells.keys())
    matrix = [["" for _ in range(max_col + 1)] for _ in range(max_row)]
    for (row, col), cell in cells.items():
        matrix[row - 1][col] = cell.value
    return matrix


def row_from_source_by_site(
    source_matrix: list[list[str]],
    site_value: str,
    site_col_zero_based: int,
) -> list[str] | None:
    target = site_value.strip()
    for row in source_matrix:
        if site_col_zero_based < len(row) and row[site_col_zero_based].strip() == target:
            return row
    return None


def row_from_source_by_col_value(
    source_matrix: list[list[str]],
    col_index: int,
    value: str,
) -> list[str] | None:
    target = value.strip()
    for row in source_matrix:
        if col_index < len(row) and row[col_index].strip() == target:
            return row
    return None


def header_col_index(headers: list[str], header_name: str) -> int | None:
    target = header_name.strip()
    for idx, val in enumerate(headers):
        if val.strip() == target:
            return idx
    return None


def safe_filename(name: str) -> str:
    out = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    out = out.strip("._")
    return out or "export"


def slugify_site(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug


def _looks_like_ipv4_token(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?", raw)
    if not m:
        return False
    octets = [int(part) for part in m.group(1).split(".")]
    if any(o < 0 or o > 255 for o in octets):
        return False
    if m.group(2) is not None:
        mask = int(m.group(2))
        if mask < 0 or mask > 32:
            return False
    return True


def apply_replacements(value: str, replacements: list[tuple[str, str]]) -> str:
    out = value
    placeholders: list[tuple[str, str]] = []

    for idx, (old, new) in enumerate(replacements):
        if not old:
            continue
        placeholder = f"__NBX_REPL_{idx}__"
        if _looks_like_ipv4_token(old):
            # Avoid replacing inside longer numeric tokens such as
            # 10.41.10.12 -> 10.40.9.11 mutating 10.41.10.128.
            pattern = rf"(?<![0-9.]){re.escape(old)}(?![0-9])"
            if re.search(pattern, out):
                out = re.sub(pattern, placeholder, out)
                placeholders.append((placeholder, new))
        else:
            if old in out:
                out = out.replace(old, placeholder)
                placeholders.append((placeholder, new))

    for placeholder, new in placeholders:
        out = out.replace(placeholder, new)

    return out


def _section_from_identifier(identifier: str) -> str:
    ident = str(identifier or "").strip()
    if not ident:
        return ""
    base = ident[:-2] if ident.endswith("-h") else ident
    labels = [
        "ip-addresses",
        "power-panels",
        "power-feeds",
        "powercables",
        "prefixroles",
        "locations",
        "devices",
        "modules",
        "cables",
        "prefix",
        "sites",
        "racks",
        "vrf",
    ]
    for label in labels:
        if base.endswith(label):
            return label
    return ""


def _unique_nonempty(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v or "").strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _normalize_d4_value(d4_value: str) -> str:
    raw = str(d4_value or "").strip()
    if not raw:
        return ""
    if raw not in D4_ALLOWED_VALUES:
        raise ValueError("D4 value must be one of 1, 2, 3, or 4.")
    return raw


def list_b2_options(xlsx_path: Path) -> list[str]:
    reader = XlsxReader(xlsx_path)
    try:
        # Netbox-Config B2 validation is Helper!C2:C14 in current workbook.
        helper_cells = reader.parse_sheet_cells("Helper")
        helper_matrix = build_sheet_matrix(helper_cells)
        vals: list[str] = []
        for row_idx in range(1, 14):  # 0-based rows 1..13 => Excel 2..14
            if row_idx < len(helper_matrix) and len(helper_matrix[row_idx]) > 2:
                vals.append(helper_matrix[row_idx][2])
        options = _unique_nonempty(vals)
        if options:
            return options
        # Fallback to current configured customer in workbook.
        cfg_cells = reader.parse_sheet_cells("Netbox-Config")
        cur = get_cell(cfg_cells, "B2").strip()
        return [cur] if cur else []
    finally:
        reader.close()


def list_d4_options(xlsx_path: Path) -> list[str]:
    reader = XlsxReader(xlsx_path)
    try:
        cfg_cells = reader.parse_sheet_cells("Netbox-Config")
        current = get_cell(cfg_cells, "D4").strip()
        options = list(D4_ALLOWED_VALUES)
        if current and current not in options:
            options.append(current)
        return options
    finally:
        reader.close()


def _source_sheet_matrix(reader: XlsxReader, b2_value: str) -> list[list[str]]:
    source_cells = reader.parse_sheet_cells(b2_value)
    source_matrix = build_sheet_matrix(source_cells)
    if len(source_matrix) < 4:
        raise ValueError(f'Source sheet "{b2_value}" is missing expected header rows.')
    return source_matrix


def _source_sheet_layout(source_matrix: list[list[str]]) -> tuple[list[str], int]:
    source_headers = source_matrix[3]
    site_col = header_col_index(source_headers, "Site")
    if site_col is None:
        # Fallback for older layouts where Site was in column H.
        site_col = 7
    return source_headers, site_col


def _find_row_in_sheet(
    source_matrix: list[list[str]],
    match_key: str,
    template_facility: str,
    template_site: str,
) -> tuple[list[str], list[str]] | None:
    source_headers, site_col = _source_sheet_layout(source_matrix)
    key_col = header_col_index(source_headers, match_key)
    old_row = None
    if key_col is not None and template_facility:
        old_row = row_from_source_by_col_value(source_matrix, key_col, template_facility)
    if old_row is None and template_site:
        old_row = row_from_source_by_site(source_matrix, template_site, site_col)
    if old_row is None:
        return None
    return source_headers, old_row


def _template_rows_from_workbook(reader: XlsxReader) -> list[list[str]]:
    if "Netbox-import" not in reader.sheet_paths:
        raise ValueError('Workbook is missing required sheet "Netbox-import".')
    cells = reader.parse_sheet_cells("Netbox-import")
    matrix = build_sheet_matrix(cells)
    rows = [list(row) for row in matrix if any(str(cell or "").strip() for cell in row)]
    if len(rows) < 2:
        raise ValueError('Workbook sheet "Netbox-import" has no usable data rows.')
    return rows


def _template_rows_from_config_filter(reader: XlsxReader, d4_value: str) -> list[list[str]]:
    config_cells = reader.parse_sheet_cells("Netbox-Config")
    config_matrix = build_sheet_matrix(config_cells)
    threshold = int(_normalize_d4_value(d4_value))
    rows: list[list[str]] = []
    for row in config_matrix[1:]:
        level = row[7] if len(row) > 7 else ""
        export_row = list(row[8:27])
        first_cell = export_row[0] if export_row else ""
        if not str(first_cell or "").strip():
            continue
        level_raw = str(level or "").strip()
        if level_raw:
            try:
                if int(level_raw) > threshold:
                    continue
            except Exception:
                continue
        rows.append(export_row)
    if len(rows) < 2:
        raise ValueError('Workbook-filtered Netbox-import data has no usable rows.')
    return rows


def list_d7_options(xlsx_path: Path, b2_value: str) -> list[str]:
    b2_value = str(b2_value or "").strip()
    if not b2_value:
        raise ValueError("B2 value is required.")
    reader = XlsxReader(xlsx_path)
    try:
        source_matrix = _source_sheet_matrix(reader, b2_value)
        headers, site_col = _source_sheet_layout(source_matrix)
        # Keep D7 options aligned with export capability: only rows that can
        # resolve G7 via match key (typically Facility-Code).
        cfg_cells = reader.parse_sheet_cells("Netbox-Config")
        match_key = get_cell(cfg_cells, "F7").strip() or "Facility-Code"
        key_col = header_col_index(headers, match_key)
        vals: list[str] = []
        for row in source_matrix[4:]:
            if len(row) <= site_col:
                continue
            site_val = row[site_col]
            if key_col is not None:
                key_val = row[key_col] if len(row) > key_col else ""
                if not str(key_val or "").strip():
                    continue
            vals.append(site_val)
        return _unique_nonempty(vals)
    finally:
        reader.close()


def build_netbox_import_export(
    xlsx_path: Path,
    template_csv_path: Path | None,
    b2_value: str,
    d7_value: str,
    d4_value: str = "",
) -> tuple[str, list[list[str]]]:
    b2_value = str(b2_value or "").strip()
    d7_value = str(d7_value or "").strip()
    d4_value = _normalize_d4_value(d4_value)
    if not b2_value:
        raise ValueError("B2 value is required.")
    if not d7_value:
        raise ValueError("D7 value is required.")
    if not xlsx_path.exists():
        raise ValueError(f"Input file not found: {xlsx_path}")
    reader = XlsxReader(xlsx_path)
    try:
        config_cells = reader.parse_sheet_cells("Netbox-Config")
        if len(build_sheet_matrix(config_cells)) < 7:
            raise ValueError("Netbox-Config sheet does not have expected structure.")

        source_matrix = _source_sheet_matrix(reader, b2_value)
        source_headers, site_col = _source_sheet_layout(source_matrix)
        match_key = get_cell(config_cells, "F7").strip() or "Facility-Code"
        key_col = header_col_index(source_headers, match_key)
        if key_col is None:
            raise ValueError(
                f'Could not find header "{match_key}" in source sheet "{b2_value}".'
            )

        workbook_d4 = get_cell(config_cells, "D4").strip()
        if d4_value and d4_value != workbook_d4:
            template_rows = _template_rows_from_config_filter(reader, d4_value)
        else:
            template_rows = _template_rows_from_workbook(reader)

        template_sample = template_rows[1]
        template_site = template_sample[2].strip() if len(template_sample) > 2 else ""
        template_slug = template_sample[3].strip() if len(template_sample) > 3 else ""
        template_facility = template_sample[8].strip() if len(template_sample) > 8 else ""

        new_row = row_from_source_by_site(source_matrix, d7_value, site_col)
        if new_row is None:
            raise ValueError(
                f'Site "{d7_value}" was not found in source sheet "{b2_value}".'
            )

        g7_value = new_row[key_col].strip()
        if not g7_value:
            raise ValueError(
                f'Could not resolve Netbox-Config!G7 value from source row for "{d7_value}".'
            )

        found_old = _find_row_in_sheet(
            source_matrix=source_matrix,
            match_key=match_key,
            template_facility=template_facility,
            template_site=template_site,
        )
        if found_old is not None:
            old_headers, old_row = found_old
        else:
            old_headers = source_headers
            old_row = None
            # Template baseline may come from a different B2 sheet (e.g., NC template
            # while exporting PTC). Search all known B2 options.
            for candidate_b2 in list_b2_options(xlsx_path):
                try:
                    candidate_matrix = _source_sheet_matrix(reader, candidate_b2)
                except Exception:
                    continue
                candidate_found = _find_row_in_sheet(
                    source_matrix=candidate_matrix,
                    match_key=match_key,
                    template_facility=template_facility,
                    template_site=template_site,
                )
                if candidate_found is not None:
                    old_headers, old_row = candidate_found
                    break
            if old_row is None:
                raise ValueError(
                    "Could not resolve template baseline row from Netbox-import template values."
                )

        replacements_map: dict[str, str] = {}
        new_header_index: dict[str, int] = {}
        for idx, header in enumerate(source_headers):
            key = str(header or "").strip()
            if key and key not in new_header_index:
                new_header_index[key] = idx

        # Header-aligned mapping avoids cross-sheet column drift when template
        # baseline is resolved from a different B2 sheet.
        for old_idx, header in enumerate(old_headers):
            key = str(header or "").strip()
            if not key:
                continue
            new_idx = new_header_index.get(key)
            if new_idx is None:
                continue
            old_v = (old_row[old_idx] if old_idx < len(old_row) else "").strip()
            new_v = (new_row[new_idx] if new_idx < len(new_row) else "").strip()
            if old_v and new_v and old_v != new_v:
                replacements_map[old_v] = new_v
        if template_site and template_site != d7_value:
            replacements_map[template_site] = d7_value
        if template_slug:
            replacements_map[template_slug] = slugify_site(d7_value)

        replacements = sorted(replacements_map.items(), key=lambda p: len(p[0]), reverse=True)
        prefix_replacements = [
            (old, new)
            for old, new in replacements
            if not (_looks_like_ipv4_token(old) and "/" not in old)
        ]
        output_matrix: list[list[str]] = []
        current_section = ""
        for row in template_rows:
            if row:
                section = _section_from_identifier(row[0])
                if section:
                    current_section = section
            row_replacements = prefix_replacements if current_section == "prefix" else replacements
            output_matrix.append([apply_replacements(cell, row_replacements) for cell in row])
        return g7_value, output_matrix
    finally:
        reader.close()


def write_export_csv(
    xlsx_path: Path,
    template_csv_path: Path | None,
    output_dir: Path,
    b2_value: str,
    d7_value: str,
    d4_value: str = "",
) -> tuple[str, Path]:
    g7_value, output_matrix = build_netbox_import_export(
        xlsx_path=xlsx_path,
        template_csv_path=template_csv_path,
        b2_value=b2_value,
        d7_value=d7_value,
        d4_value=d4_value,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_name = f"{safe_filename(g7_value)}.csv"
    output_path = output_dir / output_name
    with output_path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(output_matrix)
    return g7_value, output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export Netbox-import CSV via source-table mapping for a D7 site value."
    )
    parser.add_argument("d7_value", help="Value to use for Netbox-Config!D7 (site name).")
    parser.add_argument("--xlsx", default="data/data.xlsx", help="Path to XLSX input file.")
    parser.add_argument(
        "--b2",
        default="",
        help="Optional Netbox-Config!B2 (source customer sheet). If omitted, current workbook B2 is used.",
    )
    parser.add_argument(
        "--template-csv",
        default="data/Netbox-import.csv",
        help="Existing Netbox-import template CSV to transform.",
    )
    parser.add_argument(
        "--output-dir",
        default="data",
        help="Directory where <G7>.csv is written.",
    )
    args = parser.parse_args()

    xlsx_path = Path(args.xlsx)
    template_csv_path = Path(args.template_csv)
    output_dir = Path(args.output_dir)
    if not xlsx_path.exists():
        print(f"Input file not found: {xlsx_path}", file=sys.stderr)
        return 1
    if not template_csv_path.exists():
        print(f"Template CSV not found: {template_csv_path}", file=sys.stderr)
        return 1
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        b2_value = str(args.b2 or "").strip()
        if not b2_value:
            reader = XlsxReader(xlsx_path)
            try:
                config_cells = reader.parse_sheet_cells("Netbox-Config")
                b2_value = get_cell(config_cells, "B2").strip()
            finally:
                reader.close()
        if not b2_value:
            print("Could not resolve Netbox-Config!B2.", file=sys.stderr)
            return 1

        g7_value, output_path = write_export_csv(
            xlsx_path=xlsx_path,
            template_csv_path=template_csv_path,
            output_dir=output_dir,
            b2_value=b2_value,
            d7_value=args.d7_value,
        )
        print(f'Exported Netbox-import from template {template_csv_path}')
        print(f'B2 source sheet="{b2_value}"')
        print(f'D7 target site="{args.d7_value.strip()}"')
        print(f'Resolved G7="{g7_value}"')
        print(f"Wrote {output_path}")
        return 0
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
