from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.views import exception_handler
from django.db import transaction


def gt_exception_handler(exc, context):
    if isinstance(exc, DjangoValidationError):
        exc = exceptions.ValidationError(exc.message_dict if hasattr(exc, "message_dict") else exc.messages)
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()

    if isinstance(exc, exceptions.APIException):
        msg = "服务器未知错误"
        if isinstance(exc.detail, list):
            msg = ",".join(exc.detail)
        elif isinstance(exc.detail, dict):
            _msg = []
            for k, v in exc.detail.items():
                if isinstance(v, list):
                    v = v[0]
                if hasattr(v, "string"):
                    v = v.string
                _msg.append(f"{k}:{v}")
            msg = ",".join(_msg)
        else:
            msg = exc.detail

        return Response({"msg": msg}, status=exc.status_code)

    return exception_handler(exc, context)
