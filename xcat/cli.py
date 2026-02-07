import contextlib
import functools
import importlib
import asyncio
import os
import sys

import click

from xcat import algorithms, utils
from xcat.attack import AttackContext, Encoding, make_delay_payload
from xcat.display import display_xml
from xcat.features import detect_features, Feature
from xcat.injections import detect_injections, detect_injections_timed, Injection, injectors
from xcat.shell import shell_loop


@click.group()
@click.version_option()
def cli():
    pass


def attack_options(func):
    @cli.command()
    @click.option('-m', '--method', default='GET', show_default=True, help='HTTP method to use')
    @click.option('-h', '--headers', required=False, type=utils.HeaderFile(),
                  help='A file containing extra headers')
    @click.option('-b', '--body', required=False, type=click.File('rb'),
                  help='A file containing data to send in the request body')
    @click.option('-e', '--encode', default=Encoding.URL, type=utils.EnumType(Encoding),
                  help='Where to send the parameters (POST body or in the URL)')
    @click.option('-f', '--fast', is_flag=True, type=bool, default=False, show_default=True,
                  help='If given only retrieve the first 15 characters of strings. Can speed up retrieval.')
    @click.option('-c', '--concurrency', type=int, default=10, show_default=True,
                  help='Number of concurrent requests to make')
    @click.option('-ts', '--true-string', required=False, type=utils.NegatableString(),
                  help="Interpret this string in the response body as being a truthful request. Negate with '!'")
    @click.option('-tc', '--true-code', required=False, type=utils.NegatableInt(),
                  help="Interpret this response code as being a truthful request. Negate with '!'")
    @click.option('--enable', required=False, type=utils.FeatureChoice(),
                  help='Force enable features')
    @click.option('--disable', required=False, type=utils.FeatureChoice(),
                  help='Force disable features')
    @click.option('--oob', required=False,
                  help='IP:port to listen on for OOB attacks. This enables the OOB server.')
    @click.option('--tamper', required=False, type=click.Path(), help='Path to a script to tamper requests')
    @click.option('--inband', is_flag=True, default=False,
                  help='Use in-band extraction via response diffing (much faster, outputs raw text)')
    @click.option('--time', 'time_nesting', required=False, type=int, default=None,
                  help='Time-based blind extraction using N nested count() for delay')
    @click.argument('url')
    @click.argument('target_parameter')
    @click.argument('parameters', nargs=-1, type=utils.DictParameters())
    @click.pass_context
    @functools.wraps(func)
    def wrapper(ctx, url, target_parameter, parameters, concurrency, fast, body, headers, method,
                encode, true_string, true_code, enable, disable, oob, tamper, inband, time_nesting,
                **kwargs):
        if body and encode != 'url':
            ctx.fail('Can only use --body with url encoding')

        if inband and time_nesting:
            ctx.fail('--inband and --time are mutually exclusive')

        if not true_code and not true_string and not time_nesting:
            ctx.fail('--true-code, --true-string, or --time is required')

        if true_code or true_string:
            match_function = utils.make_match_function(true_code, true_string)
        else:
            match_function = lambda status, body: False

        if time_nesting:
            concurrency = 1

        parameters = dict(parameters)

        if target_parameter not in parameters:
            ctx.fail(f'target parameter {target_parameter} is not in the given list of parameters')

        body_bytes = None
        if body:
            body_bytes = body.read()

        tamper_function = None
        if tamper:
            if not tamper.endswith('.py'):
                ctx.fail('--tamper must be a path to a Python script')

            dirname = os.path.dirname(tamper)
            sys.path.append(dirname)
            basename = os.path.basename(tamper)
            try:
                module = importlib.import_module(basename[:-3])
            except Exception:
                ctx.fail(f'failed to import tamper script: {tamper}')
            tamper_function = getattr(module, "tamper")
            if tamper_function is None:
                ctx.fail(f'no attribute called "tamper" found in {tamper}')
            elif not callable(tamper_function):
                ctx.fail(f'"tamper" attribute in {tamper} is not callable')

        context = AttackContext(
            url=url,
            method=method,
            target_parameter=target_parameter,
            parameters=parameters,
            match_function=match_function,
            concurrency=concurrency,
            fast_mode=fast,
            body=body_bytes,
            headers=headers,
            encoding=encode,
            oob_details=oob,
            tamper_function=tamper_function,
            inband=inband,
            time_based=bool(time_nesting),
            time_delay_expr=make_delay_payload(time_nesting) if time_nesting else None,
        )

        if enable:
            context.features.update({k: True for k in enable})

        if disable:
            context.features.update({k: False for k in disable})

        return func(context, **kwargs)

    return wrapper


@attack_options
def detect(attack_context):
    try:
        payloads: list[Injection] = asyncio.run(get_injections(attack_context))
    except KeyboardInterrupt:
        return

    if not payloads:
        click.echo(click.style('Error: No injections detected', 'red'), err=True)
        exit(1)

    for payload in payloads:
        click.echo(click.style(payload.name, 'green'))
        click.echo('Example: ' + click.style(payload.example, 'yellow'))
    click.echo()

    try:
        features: list[tuple[Feature, bool]] = asyncio.run(get_features(attack_context, payloads[0]))
    except KeyboardInterrupt:
        return
    click.echo('Detected features:')
    for feature, available in features:
        click.echo(click.style(feature.name, 'blue') + ': ', nl=False)
        click.echo(click.style(str(available), 'green' if available else 'red'))


@attack_options
def run(attack_context):
    try:
        asyncio.run(start_attack(attack_context))
    except KeyboardInterrupt:
        pass


@attack_options
def shell(attack_context):
    try:
        asyncio.run(start_shell(attack_context))
    except KeyboardInterrupt:
        pass


@cli.command()
def ip():
    ip = utils.get_ip()
    if not ip:
        click.echo('Could not find an external IP', err=True)
    else:
        click.echo(ip)
    return


@cli.command()
def injections():
    click.echo(f'Supports {len(injectors)} injections:')
    for injector in injectors:
        click.echo('Name: ' + click.style(injector.name, 'bright_green'))
        formatted_example = injector.example.replace('?', click.style('?', 'red'))
        click.echo(' Example: ' + formatted_example)
        click.echo(' Tests:')
        for payload, expected in injector.test_payloads(click.style('?', 'red')):
            res = click.style('passes' if expected else 'fails', 'green' if expected else 'red')
            click.echo(f'   {payload} = {res}')


async def get_injections(context: AttackContext):
    async with context.start() as ctx:
        return await detect_injections(ctx)


async def get_injections_timed(context: AttackContext):
    async with context.start() as ctx:
        return await detect_injections_timed(ctx)


async def get_features(context: AttackContext, injection: Injection):
    # For time-based: pass injection so check() can wrap with delay
    # For normal: no injection, detect_features pre-formats payloads
    async with context.start(injection if context.time_based else None) as ctx:
        return await detect_features(ctx, injection)


@contextlib.asynccontextmanager
async def setup_context(context: AttackContext) -> AttackContext:
    if context.time_based:
        click.echo(click.style('Time-based mode: detecting injections via timing...', 'blue'))
        click.echo(f'  Delay payload: {context.time_delay_expr}')
        detected_injections, threshold = await get_injections_timed(context)
        if not detected_injections:
            click.echo(click.style(
                'Error: No injections detected via timing. '
                'Try increasing the --time nesting level.',
                'red'
            ), err=True)
            exit(1)
        click.echo(click.style(
            f'Detected: {detected_injections[0].name} '
            f'(threshold: {threshold:.2f}s)',
            'green'
        ))
        context = context._replace(time_threshold=threshold)
    else:
        detected_injections = await get_injections(context)
        if not detected_injections:
            click.echo(click.style('Error: No injections detected', 'red'), err=True)
            exit(1)

    if context.time_based:
        # For time-based: skip feature detection (each probe costs seconds).
        # Force normalize-space (XPath 1.0, always available) to avoid
        # whitespace noise. Do NOT enable substring-search or codepoint-search:
        # binary search is slower than linear for time-based because each
        # true result costs ~N seconds while false is instant.
        context.features['normalize-space'] = True
    else:
        features = await get_features(context, detected_injections[0])
        for feature, available in features:
            if feature.name in context.features:
                continue
            context.features[feature.name] = available

    async with context.start(detected_injections[0]) as ctx:
        if not context.time_based and context.features['oob-http']:
            oob_ctx_manager = ctx.start_oob_server
        else:
            oob_ctx_manager = ctx.null_context
        async with oob_ctx_manager() as oob_ctx:
            yield oob_ctx


async def start_attack(context: AttackContext):
    async with setup_context(context) as ctx:
        if ctx.inband:
            from xcat.inband import inband_extract
            lines = await inband_extract(ctx)
            if lines is not None:
                for line in lines:
                    click.echo(line)
                return
        await display_xml([await algorithms.get_nodes(ctx)])


async def start_shell(context: AttackContext):
    async with setup_context(context) as ctx:
        await shell_loop(ctx)


if __name__ == '__main__':
    cli()
