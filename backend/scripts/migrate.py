import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from alembic.config import Config
from alembic import command
from loguru import logger


def get_alembic_config() -> Config:
    alembic_ini_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini")
    config = Config(alembic_ini_path)
    return config


def upgrade(revision: str = "head") -> None:
    config = get_alembic_config()
    command.upgrade(config, revision)
    logger.info(f"Upgraded to revision: {revision}")


def downgrade(revision: str = "-1") -> None:
    config = get_alembic_config()
    command.downgrade(config, revision)
    logger.info(f"Downgraded to revision: {revision}")


def current() -> None:
    config = get_alembic_config()
    command.current(config)


def history() -> None:
    config = get_alembic_config()
    command.history(config)


def create(message: str) -> None:
    config = get_alembic_config()
    command.revision(config, message=message, autogenerate=True)
    logger.info(f"Created new migration: {message}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Database Migration Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade to a revision")
    upgrade_parser.add_argument("revision", nargs="?", default="head", help="Target revision (default: head)")

    downgrade_parser = subparsers.add_parser("downgrade", help="Downgrade to a revision")
    downgrade_parser.add_argument("revision", nargs="?", default="-1", help="Target revision (default: -1)")

    subparsers.add_parser("current", help="Show current revision")
    subparsers.add_parser("history", help="Show migration history")

    create_parser = subparsers.add_parser("create", help="Create a new migration")
    create_parser.add_argument("message", help="Migration message")

    args = parser.parse_args()

    if args.command == "upgrade":
        upgrade(args.revision)
    elif args.command == "downgrade":
        downgrade(args.revision)
    elif args.command == "current":
        current()
    elif args.command == "history":
        history()
    elif args.command == "create":
        create(args.message)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
