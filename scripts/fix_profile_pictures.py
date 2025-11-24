#!/usr/bin/env python3
"""
Diagnostic and optional fixer for profile picture storage paths.
Usage:
  python scripts/fix_profile_pictures.py [--fix]

--fix will move files into `static/uploads/<username>/profile_pictures/` and update the DB to store the relative path.
Without --fix it will only print a report.
"""
import os
import sys
from pathlib import Path
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('--fix', action='store_true', help='Move files and update DB')
parser.add_argument('--user-id', type=int, help='Only process a single user id')
args = parser.parse_args()

# Ensure the app package path is set
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app, db, safe_username
from models import User

UPLOAD_ROOT = app.config.get('UPLOAD_FOLDER', 'static/uploads')

with app.app_context():
    query = User.query
    if args.user_id:
        query = query.filter(User.id == args.user_id)

    users = query.all()

    if not users:
        print('No users found')
        sys.exit(0)

    for u in users:
        print('---')
        print(f'User id={u.id}, username={u.username}')
        pic = getattr(u, 'profile_picture', None)
        print('Stored profile_picture:', repr(pic))
        # If patient.profile_picture exists, we don't handle here (admin template uses user)

        if not pic:
            print(' No profile picture set')
            continue

        # Determine physical path(s) to check
        candidates = []
        if pic.startswith('http'):
            print('  External URL - no local file')
            continue
        if os.path.isabs(pic):
            candidates.append(pic)
        # relative to app.root_path
        candidates.append(os.path.join(app.root_path, pic))
        # relative to UPLOAD_ROOT under static
        candidates.append(os.path.join(app.root_path, UPLOAD_ROOT, os.path.basename(pic)))
        # relative to static
        candidates.append(os.path.join(app.root_path, 'static', pic))

        found = None
        for c in candidates:
            if c and os.path.exists(c):
                found = c
                break

        if found:
            print('  Found file:', found)
            # If file already in per-user profile_pictures, no action needed
            rel_root = UPLOAD_ROOT.replace('\\', '/')
            username_for = safe_username(u)
            correct_dir = os.path.join(app.root_path, rel_root, username_for, 'profile_pictures')
            os.makedirs(correct_dir, exist_ok=True)
            desired_name = os.path.basename(found)
            desired_full = os.path.join(correct_dir, desired_name)
            desired_rel = os.path.join(rel_root, username_for, 'profile_pictures', desired_name).replace('\\', '/')

            print('  Desired rel path:', desired_rel)

            if os.path.abspath(found) == os.path.abspath(desired_full):
                print('  Already in desired location; ensuring DB uses relative path')
                if pic != desired_rel:
                    if args.fix:
                        u.profile_picture = desired_rel
                        db.session.add(u)
                        db.session.commit()
                        print('   DB updated')
                    else:
                        print('   Would update DB to:', desired_rel)
                else:
                    print('   DB already correct')
            else:
                print('  File not in desired location')
                if args.fix:
                    # Move file
                    try:
                        os.replace(found, desired_full)
                        u.profile_picture = desired_rel
                        db.session.add(u)
                        db.session.commit()
                        print('   Moved file and updated DB')
                    except Exception as e:
                        print('   Failed to move/update:', e)
                else:
                    print('   Would move file to', desired_full, 'and update DB to', desired_rel)
        else:
            print('  No local file found for stored path; may be a remote URL or deleted file')

print('\nDone')
