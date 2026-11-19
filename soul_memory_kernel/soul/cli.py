"""Local commands for first-run naming and explicit family-profile maintenance."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from soul_memory_kernel.soul.core import SoulError, create_soul_config
from soul_memory_kernel.soul.profile import FamilyMember, FamilyProfileStore, ProfileError


def _default_data_dir() -> Path:
    return Path.cwd() / "data"


def _paths(args: argparse.Namespace) -> tuple[Path, Path]:
    data_dir = _default_data_dir()
    config = args.config or Path(os.environ.get("SOUL_CONFIG_PATH", data_dir / "soul.json"))
    profile = args.family_db or Path(
        os.environ.get("FAMILY_PROFILE_DB", data_dir / "family.sqlite3")
    )
    return config, profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-memory-soul", description="本地 Soul 与家庭静态档案维护")
    parser.add_argument("--config", type=Path, help="Soul JSON 路径")
    parser.add_argument("--family-db", type=Path, help="家庭档案 SQLite 路径")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="首次命名并创建本地 Soul 配置")
    init_parser.add_argument("--name", help="AI 名字；不传时交互询问一次")

    profile_parser = commands.add_parser("profile", help="维护本地静态家庭档案")
    profile_commands = profile_parser.add_subparsers(dest="profile_command", required=True)
    add = profile_commands.add_parser("add", help="交互式新增或更新一位成员")
    add.add_argument("--id", help="本地稳定 ID，例如 parent_1")
    profile_commands.add_parser("list", help="列出本地成员档案")
    remove = profile_commands.add_parser("remove", help="删除本地成员记录")
    remove.add_argument("id")

    args = parser.parse_args(argv)
    config_path, profile_path = _paths(args)
    try:
        if args.command == "init":
            name = args.name
            if name is None:
                name = input("你想给我起什么名字？ ")
            create_soul_config(config_path, name)
            print(f"已保存 Soul 配置：{config_path}")
            return 0
        store = FamilyProfileStore(profile_path)
        if args.profile_command == "add":
            member_id = args.id or input("本地稳定 ID（如 parent_1）：").strip()
            name = input("成员称呼：")
            role = input("成员角色（如 parent / child / other）：")
            age_text = input("年龄（可留空）：").strip()
            relationship = input("与家庭的关系：")
            try:
                age = int(age_text) if age_text else None
            except ValueError as exc:
                raise ProfileError("年龄必须是整数或留空") from exc
            store.upsert(
                FamilyMember(
                    id=member_id,
                    name=name,
                    role=role,
                    age=age,
                    relationship=relationship,
                )
            )
            print(f"已保存本地成员档案：{member_id}")
            return 0
        if args.profile_command == "list":
            for member in store.list_members():
                age = "年龄未填写" if member.age is None else f"{member.age} 岁"
                print(f"{member.id}\t{member.name}\t{age}\t{member.relationship}")
            return 0
        removed = store.remove(args.id)
        print("已删除成员档案。" if removed else "没有找到该成员档案。")
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\n未完成交互，退出。")
        return 0
    except (SoulError, ProfileError, OSError) as exc:
        print(f"本地配置错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
