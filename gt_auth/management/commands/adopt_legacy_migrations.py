"""Record a verified pre-migration schema without running CREATE/DROP statements."""
from django.core.management.base import BaseCommand, CommandError
from django.db import connections, transaction
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder


BASELINE = {
    "gt_auth": ("0001_initial", "0002_initial"),
    "gt_admin": ("0001_initial", "0002_initial"),
    "gt_alumni": ("0001_initial", "0002_initial"),
    "gt_coin": ("0001_initial",),
    "gt_file": ("0001_initial",),
    "gt_forum": ("0001_initial",),
}


class Command(BaseCommand):
    help = "Inspect an original schema without project migration history; --apply records only validated baseline migrations."
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument("--database", default="default")
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        connection = connections[options["database"]]
        loader = MigrationLoader(connection)
        targets = [(app, names[-1]) for app, names in BASELINE.items()]
        baseline = [(app, name) for app, names in BASELINE.items() for name in names]
        missing = [item for item in baseline if item not in loader.applied_migrations]
        if not missing:
            self.stdout.write("初始迁移记录已经齐全，无需接续。")
            return
        if any(app in BASELINE and (app, name) not in baseline for app, name in loader.applied_migrations):
            raise CommandError("已有部分升级迁移，不能按原始结构接续；请先核对迁移历史。")
        state = loader.project_state(targets)
        with connection.cursor() as cursor:
            tables = set(connection.introspection.table_names(cursor))
            errors = []
            count = 0
            for model in state.apps.get_models(include_auto_created=True):
                if model._meta.app_label not in BASELINE or not model._meta.managed:
                    continue
                table = model._meta.db_table
                if table not in tables:
                    errors.append(f"缺表 {table}")
                    continue
                actual = {field.name for field in connection.introspection.get_table_description(cursor, table)}
                expected = {field.column for field in model._meta.local_concrete_fields}
                if actual != expected:
                    errors.append(f"{table} 字段不匹配：缺少 {sorted(expected-actual)}，多出 {sorted(actual-expected)}")
                    continue
                constraints = connection.introspection.get_constraints(cursor, table)
                primary = {tuple(item["columns"]) for item in constraints.values() if item.get("primary_key")}
                if (model._meta.pk.column,) not in primary:
                    errors.append(f"{table} 主键不匹配")
                foreign = {tuple(item["foreign_key"]) for item in constraints.values() if item.get("foreign_key")}
                for field in model._meta.local_concrete_fields:
                    if field.is_relation and (field.many_to_one or field.one_to_one) and field.db_constraint:
                        target = (field.related_model._meta.db_table, field.target_field.column)
                        if target not in foreign:
                            errors.append(f"{table}.{field.column} 外键不匹配")
                count += 1
        if errors:
            raise CommandError("结构检查未通过，不会改写迁移记录：\n" + "\n".join(errors))
        self.stdout.write(f"已核对 {count} 个原始业务表的字段、主键和外键。待补记：")
        for app, name in missing:
            self.stdout.write(f"  {app}.{name}")
        if not options["apply"]:
            self.stdout.write("只读检查完成。备份并核对旧部署版本后，可加 --apply 补记，再运行 migrate。")
            return
        with transaction.atomic(using=options["database"]):
            recorder = MigrationRecorder(connection)
            for app, name in missing:
                recorder.record_applied(app, name)
        self.stdout.write("初始迁移记录已接续，业务表和业务数据未修改。请运行 migrate 应用新的安全结构。")
