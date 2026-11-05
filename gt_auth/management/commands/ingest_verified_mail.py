"""Local MTA adapter. The sender/authentication envelope must come from trusted infrastructure."""
import json
import sys
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from rest_framework.exceptions import ValidationError
from gt_auth.advanced_views import accept_verified_mail


class Command(BaseCommand):
    help = "Import a DMARC-verified mail event from a trusted receiving mail system (JSON file or stdin)."

    def add_arguments(self, parser):
        parser.add_argument("--event", default="-", help="Path to trusted JSON event; '-' reads stdin")

    def handle(self, *args, **options):
        try:
            if options["event"] == "-":
                raw = sys.stdin.buffer.read(100001)
            else:
                with Path(options["event"]).open("rb") as source:
                    raw = source.read(100001)
            if len(raw) > 100000:
                raise CommandError("邮件事件超过 100000 字节")
            event = json.loads(raw.decode("utf-8"))
            row = accept_verified_mail(event)
        except (OSError, ValueError, UnicodeError, ValidationError) as exc:
            raise CommandError("邮件事件未通过认证格式或身份校验") from exc
        self.stdout.write(f"{row.pk} {row.status}")
