import re
import urllib.request
from collections.abc import Callable

import click

from .features import features


def get_ip():
    with urllib.request.urlopen('https://api.ipify.org') as content:
        return re.search(r'[0-9]+(?:\.[0-9]+){3}', str(content.read())).group(0)


class FeatureChoice(click.types.StringParamType):
    def convert(self, value, param, ctx):
        value = super().convert(value, param, ctx)
        feature_names = {feature.name for feature in features}
        given_names = set(value.split(','))
        unknown_features = given_names - feature_names
        if unknown_features:
            self.fail(f'Unknown features: {", ".join(unknown_features)}.')
        return given_names


class EnumType(click.Choice):
    def __init__(self, enum):
        self._enum = enum
        super().__init__(enum.__members__)

    def convert(self, value, param, ctx):
        if isinstance(value, self._enum):
            return value
        value = value.upper()
        return self._enum[super().convert(value, param, ctx)]


class HeaderFile(click.File):
    def __init__(self):
        super().__init__(mode='r')

    def convert(self, value, param, ctx):
        open_file = super().convert(value, param, ctx)

        # ToDO: replace this with the new aiohttp header parser
        #  https://github.com/aio-libs/aiohttp/blob/15857de31e57574be595ac3fda673852eef64b63/aiohttp/http_parser.py#L76

        with open_file as fd:
            lines = (line.strip() for line in open_file)
            headers = {}
            for line in lines:
                if not line:
                    continue
                try:
                    key, value = line.split(':', 1)
                except ValueError:
                    self.fail(f'Not a valid header line: {line}')

                headers[key] = value.strip()

            return headers


class DictParameters(click.ParamType):
    def convert(self, value, param, ctx):
        try:
            key, value = value.split('=', 1)
        except ValueError:
            self.fail(f'Argument "{value}" must be in a key=value format')

        return key, value


class Negatable(click.ParamType):
    def convert(self, value, param, ctx):
        negate = False
        if value.startswith('!'):
            negate = True
            value = value[1:]

        return negate, self.validate(value)

    def validate(self, value):
        raise NotImplementedError()


class NegatableInt(Negatable):
    name = 'str'

    def validate(self, value):
        try:
            return int(value)
        except ValueError:
            self.fail(f'{value} is not an integer.')


class NegatableString(Negatable):
    name = 'str'

    def validate(self, value):
        return value


def make_match_function(true_code: tuple[bool, int] = None,
                        true_string: tuple[bool, str] = None,
                        true_regex: tuple[bool, str] = None,
                        true_location: tuple[bool, str] = None) -> Callable[[int, str, dict], bool]:
    """Build the oracle. Each supplied matcher must agree (logical AND) for the
    response to count as 'true'. The oracle sees the status, the (final) body,
    and a structured ``extra`` observation so it can also match on the redirect
    Location / final URL even when aiohttp transparently followed the redirect.

    Every matcher supports a leading '!' negation (already parsed into the
    bool flag by the Negatable* CLI types).
    """
    compiled_regex = None
    if true_regex is not None:
        negate_regex, pattern = true_regex
        compiled_regex = (negate_regex, re.compile(pattern))

    def check_code(response_code: int):
        if true_code is None:
            return True

        negate_code, expected_code = true_code
        if negate_code:
            return response_code != expected_code

        return response_code == expected_code

    def check_content(content: str):
        if true_string is None:
            return True

        negate_string, expected_string = true_string
        if negate_string:
            return expected_string not in content

        return expected_string in content

    def check_regex(content: str):
        if compiled_regex is None:
            return True

        negate_regex, pattern = compiled_regex
        found = pattern.search(content) is not None
        return not found if negate_regex else found

    def check_location(extra: dict):
        if true_location is None:
            return True

        negate_location, expected = true_location
        haystack = ' '.join(part for part in [
            extra.get('location', ''),
            extra.get('final_url', ''),
            *extra.get('history', []),
        ] if part)
        present = expected in haystack
        return not present if negate_location else present

    return lambda code, content, extra: (
        check_code(code) and check_content(content)
        and check_regex(content) and check_location(extra)
    )
