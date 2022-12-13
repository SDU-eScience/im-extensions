from ipahttp import ipahttp
from common import *
import re


################################################################################


ipa = None
def ipa_authenticate(username, password, server, cert):
	global ipa
	ipa = ipahttp(server, cert)
	return ipa.auth_password(username, password)


################################################################################


def ipa_extract_users(result):
    members = []
    users = set()

    if result.get('member'):
        members.extend(result['member'])
    if result.get('memberindirect'):
        members.extend(result['memberindirect'])

    for user in members:
        user = re.search('uid=(.*?),', user)
        if user:
            users.add(user.group(1))

    return list(users)


def ipa_handle_error(result, type):
    error = result.get('error')
    if not error:
        return
    code = error['code']
    if code == 4001:
        raise NameError('ipa %s does not exist' % type)
    elif code == 4002:
        raise NameError('ipa %s already exists' % type)
    elif code == 4202:
        pass
    elif code == 3009:
        name = error['data']['name']
        raise ValueError('invalid ipa variable: %s' % name)
    else:
        raise RuntimeError('unhandled ipa error %d' % code)


################################################################################


"""
ipa_user_create()
  create a new ipa user
function arguments
  [m] user           : username
  [m] firstname      : first name
  [m] lastname       : last name
  [o] email          : email address
  [o] employeenumber : employee number
return values
  uid                : user id
  gid                : group id
"""
def ipa_user_create(args):
    rets = {}
    opts = {}
    user = args.get('user')
    email = args.get('email')

    if not user:
        raise ValueError('missing variable: user')

    if not validate_name(user):
        raise ValueError('invalid variable: user')

    if email and not validate_mail(email):
        raise ValueError('invalid variable: email')

    if not args.get('firstname'):
        raise ValueError('missing variable: firstname')

    if not args.get('lastname'):
        raise ValueError('missing variable: lastname')

    if args.get('employeenumber'):
        opts['employeenumber'] = args['employeenumber']

    if email:
        opts['mail'] = email

    result = ipa.user_add(user, args['firstname'], args['lastname'], opts)
    ipa_handle_error(result, 'user')
    result = result.get('result')

    rets['uid'] = int(result['uidnumber'][0])
    rets['gid'] = int(result['gidnumber'][0])
    return rets


"""
ipa_user_query()
  return information about an existing ipa user
function arguments
  [m] user         : username
return values
  firstname        : first name
  lastname         : last name
  email            : email address
  sshkeys          : list of public ssh keys
  uid              : user id
  gid              : group id
  employeenumber   : employee number
"""
def ipa_user_query(args):
    rets = {}
    user = args.get('user')

    if not user:
        raise ValueError('missing variable: user')

    result = ipa.user_show(user)
    ipa_handle_error(result, 'user')
    result = result.get('result')

    rets['firstname'] = result['givenname'][0]
    rets['lastname'] = result['sn'][0]
    rets['email'] = result['mail'][0]
    rets['uid'] = int(result['uidnumber'][0])
    rets['gid'] = int(result['gidnumber'][0])
    rets['employeenumber'] = result['employeeNumber'][0]

    count = result.get('sshpubkeyfp', [])
    count = len(count)
    keys = []
    for n in range(count):
        tmp = result['sshpubkeyfp'][n]
        p = re.search('(.*?) ((.*) )?\((.*)\)', tmp)
        tmp = result['ipaSshPubKey'][n]['__base64__']
        if p.group(3):
            tmp = '{0} {1} {2}'.format(p.group(4), tmp, p.group(3))
        else:
            tmp = '{0} {1}'.format(p.group(4), tmp)
        keys.append(tmp)

    rets['sshkeys'] = keys
    return rets


"""
ipa_user_find()
  search for an ipa user
function arguments
  [o] user           : username
  [o] email          : email address
  [o] employeenumber : employee number
return values
  users              : list of matching users
"""
def ipa_user_find(args):
    rets = {}
    opts = {}

    if args.get('user'):
        opts['uid'] = args['user']

    if args.get('email'):
        opts['mail'] = args['email']

    if args.get('employeenumber'):
        opts['employeenumber'] = args['employeenumber']

    if not opts:
        raise ValueError('no search options specified')

    result = ipa.user_find(opts)
    ipa_handle_error(result, 'user')
    result = result.get('result')

    rets['users'] = []
    for user in result:
        rets['users'].append(user['uid'][0])

    return rets


"""
ipa_user_modify()
  modify an existing ipa user
function arguments
  [m] user           : username
  [o] firstname      : first name
  [o] lastname       : last name
  [o] email          : email address
  [o] sshpubkey      : list of public ssh keys
  [o] employeenumber : employee number
return values
  none
"""
def ipa_user_modify(args):
    rets = {}
    opts = {}
    user = args.get('user')
    email = args.get('email')

    if not user:
        raise ValueError('missing variable: user')

    if args.get('firstname'):
        opts['givenname'] = args['firstname']

    if args.get('lastname'):
        opts['sn'] = args['lastname']

    if args.get('employeenumber'):
        opts['employeenumber'] = args['employeenumber']

    if email and not validate_mail(email):
        raise ValueError('invalid variable: email')

    if email:
        opts['mail'] = email

    if args.get('sshpubkey'):
        opts['ipasshpubkey'] = args['sshpubkey']

    if not len(opts):
        return rets

    result = ipa.user_mod(user, opts)
    ipa_handle_error(result, 'user')

    return rets


"""
ipa_user_delete()
  delete an existing ipa user
function arguments
  [m] user         : username
return values
  none
"""
def ipa_user_delete(args):
    rets = {}
    user = args.get('user')

    if not user:
        raise ValueError('missing variable: user')

    result = ipa.user_del(user)
    ipa_handle_error(result, 'user')

    return rets


"""
ipa_group_query()
  return information about an existing ipa group
function arguments
  [m] group        : group name
return values
  gid              : group id
  users            : list of users
  description      : free text description
"""
def ipa_group_query(args):
    rets = {}
    group = args.get('group')

    if not group:
        raise ValueError('missing variable: group')

    result = ipa.group_show(group)
    ipa_handle_error(result, 'group')
    result = result.get('result')

    description = result.get('description', '')
    if description:
        description = description[0]

    rets['description'] = description
    rets['gid'] = int(result['gidnumber'][0])
    rets['users'] = ipa_extract_users(result)
    return rets


"""
ipa_group_find()
  search for an ipa group
function arguments
  [o] group          : group name
  [o] gid            : the group id
return values
  groups             : list of matching groups
"""
def ipa_group_find(args):
    rets = {}
    opts = {}

    if args.get('group'):
        opts['cn'] = args['group']

    if args.get('gid'):
        opts['gidnumber'] = args['gid']

    if not opts:
        raise ValueError('no search options specified')

    result = ipa.group_find(opts)
    ipa_handle_error(result, 'group')
    result = result.get('result')

    rets['groups'] = []
    for group in result:
        rets['groups'].append(group['cn'][0])

    return rets


"""
ipa_group_create()
  create a new ipa group
function arguments
  [m] group        : group name
  [o] gid          : the group id
  [o] description  : free text description
return values
  gid              : group id
"""
def ipa_group_create(args):
    rets = {}
    group = args.get('group')
    description = args.get('description')
    gid = args.get('gid')

    if not group:
        raise ValueError('missing variable: group')

    if not validate_name(group):
        raise ValueError('invalid variable: group')

    if gid is not None:
        try:
            gid = int(gid)
        except:
            raise ValueError('invalid variable: gid')

    if not description:
        description = ''

    result = ipa.group_add(group, gid=gid, description=description)
    ipa_handle_error(result, 'group')
    result = result.get('result')

    rets['gid'] = int(result['gidnumber'][0])
    return rets


"""
ipa_group_delete()
  delete an existing ipa group
function arguments
  [m] group        : group name
return values
  none
"""
def ipa_group_delete(args):
    rets = {}
    group = args.get('group')

    if not group:
        raise ValueError('missing variable: group')

    result = ipa.group_del(group)
    ipa_handle_error(result, 'group')

    return rets


"""
ipa_group_add_user()
  add user to group
function arguments
  [m] group        : group name
  [m] user         : username
return values
  none
"""
def ipa_group_add_user(args):
    rets = {}
    group = args.get('group')
    user = args.get('user')

    if not group:
        raise ValueError('missing variable: group')

    if not user:
        raise ValueError('missing variable: user')

    result = ipa.group_add_users(group, user)
    ipa_handle_error(result, 'group')
    failed = result.get('failed')
    result = result.get('result')

    if not failed:
        return rets
    else:
        failed = failed['member']['user']

    if not failed:
        return rets
    else:
        text = failed[0][1].lower()

    if 'already' in text:
        return rets

    if 'no matching' in text:
        raise NameError('ipa user not found')

    raise RuntimeError('unhandled ipa error: %s' % text)
    return rets


"""
ipa_group_remove_user()
  remove user from group
function arguments
  [m] group        : group name
  [m] user         : username
return values
  none
"""
def ipa_group_remove_user(args):
    rets = {}
    group = args.get('group')
    user = args.get('user')

    if not group:
        raise ValueError('missing variable: group')

    if not user:
        raise ValueError('missing variable: user')

    result = ipa.user_show(user)
    ipa_handle_error(result, 'user')

    result = ipa.group_remove_users(group, user)
    ipa_handle_error(result, 'group')
    failed = result.get('failed')
    result = result.get('result')

    if not failed:
        return rets
    else:
        failed = failed['member']['user']

    if not failed:
        return rets
    else:
        text = failed[0][1].lower()

    if 'not a member' in text:
        return rets

    raise RuntimeError('unhandled ipa error: %s' % text)
    return rets


"""
ipa_group_add_group()
  add group to group
function arguments
  [m] parent       : parent group name
  [m] group        : group to add
return values
  none
"""
def ipa_group_add_group(args):
    rets = {}
    parent = args.get('parent')
    group = args.get('group')

    if not parent:
        raise ValueError('missing variable: parent')

    if not group:
        raise ValueError('missing variable: group')

    result = ipa.group_add_groups(parent, group)
    ipa_handle_error(result, 'group')
    failed = result.get('failed')
    result = result.get('result')

    if not failed:
        return rets
    else:
        failed = failed['member']['group']

    if not failed:
        return rets
    else:
        text = failed[0][1].lower()

    if 'already' in text:
        return rets

    if 'no matching' in text:
        raise NameError('ipa group not found')

    raise RuntimeError('unhandled ipa error: %s' % text)
    return rets


"""
ipa_group_remove_group()
  remove group from group
function arguments
  [m] parent       : parent group name
  [m] group        : group to add
return values
  none
"""
def ipa_group_remove_group(args):
    rets = {}
    parent = args.get('parent')
    group = args.get('group')

    if not parent:
        raise ValueError('missing variable: parent')

    if not group:
        raise ValueError('missing variable: group')

    result = ipa.group_show(group)
    ipa_handle_error(result, 'group')

    result = ipa.group_remove_groups(parent, group)
    ipa_handle_error(result, 'group')
    failed = result.get('failed')
    result = result.get('result')

    if not failed:
        return rets
    else:
        failed = failed['member']['group']

    if not failed:
        return rets
    else:
        text = failed[0][1].lower()

    if 'not a member' in text:
        return rets

    raise RuntimeError('unhandled ipa error: %s' % text)
    return rets
