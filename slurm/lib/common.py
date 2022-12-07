import subprocess
import re

def run_command(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result.stdout = result.stdout.decode().strip()
    result.stderr = result.stderr.decode().strip()
    return result

def validate_mail(mail):
    if re.search('^([^@\s]+)@([^@\s]+)\.([^@\s]+)$', mail):
        return True
    else:
        return False

def validate_name(name):
    if re.search('^([a-z][a-z0-9_-]+)$', name):
        return True
    else:
        return False

def get_group_by_gid(gid):
    result = run_command(['getent', 'group', str(gid)])
    if result.returncode != 0:
        return None
    return result.stdout.split(':')[0]

def get_username_by_uid(uid):
    result = run_command(['getent', 'passwd', str(uid)])
    if result.returncode != 0:
        return None
    return result.stdout.split(':')[0]

def get_gid_by_group(name):
    result = run_command(['getent', 'group', name])
    if result.returncode != 0:
        return None
    return int(result.stdout.split(':')[2])

def clear_sssd_cache():
    run_command(['sudo', '/sbin/sss_cache', '-E'])
