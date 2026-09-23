import argparse
import asyncio
import json
import sys

from app import repository
from app.cache import RedisStore, build_client
from app.config import get_settings
from app.db import build_engine, build_sessionmaker
from app.routers.login import MIN_PASSWORD_LENGTH
from app.security.passwords import PasswordService


async def list_users(sessionmaker) -> int:
    async with sessionmaker() as session:
        users = await repository.list_users(session)
    rows = [
        {
            "username": u.username,
            "email": u.email,
            "groups": u.groups,
            "active": u.is_active,
            "must_change_password": u.must_change_password,
        }
        for u in users
    ]
    print(json.dumps(rows))
    return 0


async def set_password(sessionmaker, settings, redis: RedisStore, username: str, password: str) -> int:
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"password must be at least {MIN_PASSWORD_LENGTH} characters", file=sys.stderr)
        return 1

    async with sessionmaker() as session:
        user = await repository.get_user_by_username(session, username)
        if user is None:
            print(f"no user named {username}", file=sys.stderr)
            return 1
        await repository.set_password(session, PasswordService(settings), user, password)
        await repository.require_password_change(session, user)

    await redis.delete_user_sessions(user.id)

    print(json.dumps({"username": user.username, "email": user.email}))
    return 0


async def run(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)
    try:
        if args.command == "list-users":
            return await list_users(sessionmaker)
        redis_client = build_client(settings)
        try:
            return await set_password(
                sessionmaker,
                settings,
                RedisStore(settings, redis_client),
                args.username,
                sys.stdin.readline().rstrip("\n"),
            )
        finally:
            await redis_client.aclose()
    finally:
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-users")
    reset = commands.add_parser("set-password", help="reads the new password from stdin")
    reset.add_argument("username")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
