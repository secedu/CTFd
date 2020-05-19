import datetime
import re
import jwt

from flask import current_app as app
from flask import request, session

from CTFd.cache import cache
from CTFd.constants.users import UserAttrs
from CTFd.constants.teams import TeamAttrs
from CTFd.models import Fails, Users, db, Teams, Tracking
from CTFd.utils import get_config


def get_current_user():
    if authed():
        user = Users.query.filter_by(id=session["id"]).first()
        return user
    else:
        return None


def get_current_user_attrs():
    if authed():
        return get_user_attrs(user_id=session["id"])
    else:
        return None


@cache.memoize(timeout=30)
def get_user_attrs(user_id):
    user = Users.query.filter_by(id=user_id).first()
    if user:
        d = {}
        for field in UserAttrs._fields:
            d[field] = getattr(user, field)
        return UserAttrs(**d)
    return None


def get_current_team():
    if authed():
        user = get_current_user()
        return user.team
    else:
        return None


def get_current_team_attrs():
    if authed():
        user = get_user_attrs(user_id=session["id"])
        if user.team_id:
            return get_team_attrs(team_id=user.team_id)
    return None


@cache.memoize(timeout=30)
def get_team_attrs(team_id):
    team = Teams.query.filter_by(id=team_id).first()
    if team:
        d = {}
        for field in TeamAttrs._fields:
            d[field] = getattr(team, field)
        return TeamAttrs(**d)
    return None


def get_current_user_type(fallback=None):
    if authed():
        user = get_current_user_attrs()
        return user.type
    else:
        return fallback


def authed():
    try:
        if bool(session.get("id", False)):
            return True
        pemfile = open("/jwtRS256.key.pub", 'r')
        keystring = pemfile.read()
        pemfile.close()
        decoded = jwt.decode(request.headers.get('X-CTFProxy-JWT'), keystring, algorithm='RS256')
        username = decoded['username'].decode('utf-8')
        displayname = decoded['displayname'].decode('utf-8')
        user = Users.query.filter_by(email=username).first()
        if user is not None:
            session["id"] = user.id
        else:
            user = Users(
                name=displayname,
                email=username,
                verified=True,
                type="admin" if "ctfd-admin" in [x.split("@")[0] for x in decoded['groups']] else "user",
            )
            db.session.add(user)
            db.session.commit()
            db.session.flush()
            session["id"] = user.id
            db.session.close()
        return True
    except:
        return False


def is_admin():
    if authed():
        user = get_current_user_attrs()
        return user.type == "admin"
    else:
        return False


def is_verified():
    if get_config("verify_emails"):
        user = get_current_user_attrs()
        if user:
            return user.verified
        else:
            return False
    else:
        return True


def get_ip(req=None):
    if req is None:
        req = request
    if req.headers.get('X-CTFProxy-Remote-Addr') != "":
        return request.headers.get('X-CTFProxy-Remote-Addr')
    return req.remote_addr


def get_current_user_recent_ips():
    if authed():
        return get_user_recent_ips(user_id=session["id"])
    else:
        return None


@cache.memoize(timeout=60)
def get_user_recent_ips(user_id):
    hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
    addrs = (
        Tracking.query.with_entities(Tracking.ip.distinct())
        .filter(Tracking.user_id == user_id, Tracking.date >= hour_ago)
        .all()
    )
    return set([ip for (ip,) in addrs])


def get_wrong_submissions_per_minute(account_id):
    """
    Get incorrect submissions per minute.

    :param account_id:
    :return:
    """
    one_min_ago = datetime.datetime.utcnow() + datetime.timedelta(minutes=-1)
    fails = (
        db.session.query(Fails)
        .filter(Fails.account_id == account_id, Fails.date >= one_min_ago)
        .all()
    )
    return len(fails)
