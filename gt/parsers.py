from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser


class DepthCheckedJSONParser(JSONParser):
    """Report decoder nesting failures as invalid requests, not server errors."""
    def parse(self, stream, media_type=None, parser_context=None):
        try:
            return super().parse(stream, media_type=media_type, parser_context=parser_context)
        except RecursionError as exc:
            raise ParseError("JSON nesting is too deep") from exc


class ObjectJSONParser(DepthCheckedJSONParser):
    """Authentication request bodies have named fields, never arrays or scalars."""
    def parse(self, stream, media_type=None, parser_context=None):
        data = super().parse(stream, media_type=media_type, parser_context=parser_context)
        if not isinstance(data, dict):
            raise ParseError("请求内容必须为 JSON 对象")
        return data


AUTH_PARSERS = [ObjectJSONParser, FormParser, MultiPartParser]
