#!/bin/sh
[ "$DJANGO_SETTINGS_MODULE" ] || export DJANGO_SETTINGS_MODULE=settings
exec python -m askbot.invites "$@"
