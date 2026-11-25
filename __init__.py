"""Hermes Agent plugin entry point for originveil."""

from pathlib import Path

from . import schemas, tools

TOOLS = (
    (schemas.AUDIT, tools.audit),
    (schemas.LAST_REPORT, tools.last_report),
    (schemas.ADD_DOMAIN, tools.add_domain),
    (schemas.VERIFY_DOMAIN, tools.verify_domain),
    (schemas.LIST_DOMAINS, tools.list_domains),
    (schemas.REMOVE_DOMAIN, tools.remove_domain),
)


def register(ctx):
    get = getattr(ctx, "get_config", None)
    settings = {}
    if callable(get):
        settings = {
            "config_path": get("config_path", default=""),
            "report_dir": get("report_dir", default="/var/lib/originveil"),
            "vantage": get("vantage", default="local"),
            "allow_chat_origin_ip": get("allow_chat_origin_ip", default=False) is True,
        }
    tools.configure(settings, getattr(ctx, "state", None))

    for schema, handler in TOOLS:
        ctx.register_tool(name=schema["name"], toolset="plugin_originveil", schema=schema, handler=handler)

    register_skill = getattr(ctx, "register_skill", None)
    if callable(register_skill):
        skills = Path(__file__).resolve().parent / "skills"
        for child in sorted(skills.iterdir()) if skills.is_dir() else []:
            skill_md = child / "SKILL.md"
            if skill_md.is_file():
                register_skill(child.name, skill_md)
