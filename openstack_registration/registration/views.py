#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseRedirect, QueryDict
from django.contrib.auth.decorators import login_required
from django.contrib import auth
from openstack_registration.settings import GLOBAL_CONFIG
from Backend import OpenLdap
from registration.exceptions import InvalidX500DN
from registration.utils import *
import urllib2


LOGGER = logging.getLogger("registration")
LOGGER_ERROR = logging.getLogger("registration_error")


def user_is_authenticate(request):
    """

    :param request:
    :return:
    """
    data = {}
    data['status'] = 'False'
    if request.user.is_authenticated():
        data['status'] = 'True'
        data['user'] = str(request.user)
    return JsonResponse(data)


@login_required()
def user_is_admin(request,
                  spec=None):
    """

    :param request:
    :return:
    """
    data = {}
    data['admin'] = 'False'
    user = UserInfo.objects.filter(username=request.user)

    if spec == 'dataTable':
        data['list'] = {}
        final_list = []
        admin = UserInfo.objects.filter(admin=True)

        for each in admin:
            tmp = {}
            username = each.username
            tmp['uid'] = username
            tmp['icon'] = ''
            final_list.append(tmp)

        data['list'] = final_list
        return JsonResponse(data)

    if spec == 'list':
        data['list'] = {}
        final_list = []
        admin = UserInfo.objects.filter(admin=True)

        for each in admin:
            tmp = {}
            username = each.username
            tmp['uid'] = username
            tmp['icon'] = ''
            final_list.append(tmp)

        data['list'] = final_list
        return data

    if user:
        is_admin = user[0].admin
        if is_admin is True:
            data['admin'] = 'True'
    if spec == 'python':
        return data
    else:
        return JsonResponse(data)


@login_required()
def logs_dispatcher(request):
    if user_is_admin(request, spec='python')['admin'] != 'False':
        if request.method == 'GET'\
                and 'version' in request.GET:
             return logs_get_json(request)
        else:
            return logs_get_html(request)
    else:
        return redirect('/')


@login_required()
def logs_get_json(request):
    # pass
    data = {}
    log_file = open("/var/log/registration/registration.log", "r")
    lines = log_file.readlines()
    log_file.close()
    version = request.GET['version']
    filtered = ''

    if 'filter' in request.GET and request.GET['filter'] != '':
        # search = str(request.GET['filter'].lower().encode('utf-8'))
        search = str(request.GET['filter'].encode('utf-8'))
        if version == 'actions':
            for line in lines:
                # if line.lower().__contains__(search)\
                #         and line.__contains__("CREATED")\
                #         or line.lower().__contains__(search)\
                #         and line.__contains__("MODIFIED")\
                #         or line.lower().__contains__(search)\
                #         and line.__contains__("CONNECTED"):
                if line.__contains__(search)\
                        and (line.__contains__("CREATED")
                        or line.__contains__("MODIFIED")
                        or line.__contains__("LOGOUT")
                        or line.__contains__("LOGIN")):
                    filtered = line + filtered
        elif version == 'full':
            for line in lines:
                # if line.lower().__contains__(search):
                if line.__contains__(search):
                    filtered = line + filtered
    else:
        if version == 'actions':
            for each in lines:
                if each.__contains__("CREATE") or each.__contains__("MODIFIED") or each.__contains__("LOGIN") or each.__contains__("LOGOUT"):
                    filtered = each + filtered
        elif version == 'full':
            for each in lines:
                filtered = each + filtered

    data['logs'] = filtered
    return JsonResponse(data)


@login_required()
def logs_get_html(request):
    return render(request, 'logs_get_html.html')


@login_required()
def admin_dispatcher(request):
    """

    :param request:
    :return:
    """
    if user_is_admin(request, spec='python')['admin'] != 'False':
        if request.method == 'GET':
            if 'format' in request.GET\
                and 'email' in request.GET\
                and request.GET['format'] == 'json'\
                and request.GET['email'] == 'bar':
                return user_get_json(request)
            elif 'format' in request.GET\
                and 'spec' in request.GET\
                and request.GET['format'] == 'json'\
                and request.GET['spec'] == 'dataTable':
                return user_is_admin(request, spec='dataTable')
            elif 'format' in request.GET\
                and request.GET['format'] == 'json':
                return admin_get_json(request)
            else:
                return admin_get_html(request)
        elif request.method == 'PUT':
            return admin_put_json(request)
        elif request.method == 'POST':
            return admin_post_json(request)
    else:
        return redirect('/')


@login_required()
def admin_get_json(request):
    """

    :param request:
    :return:
    """
    data = {}
    user = UserInfo.objects.filter(username=str(request.user))
    counter = user[0].countForce
    data['counter'] = counter
    return JsonResponse(data)


@login_required()
def admin_post_json(request):
    """

    :param request:
    :return:
    """
    attrs = {}
    data = QueryDict(request.body).dict()
    group = normalize_string(data['group'])
    desc = normalize_string(data['desc'], option='name')

    if group != unicode(data['group']).encode(encoding='utf-8') or desc != unicode(data['desc']).encode(encoding='utf-8'):
    # if str(group) != str(data['group']) or str(desc) != str(data['desc']):
        attrs['group'] = group
        attrs['desc'] = desc
        attrs['status'] = 'change'
    else:
        ldap = OpenLdap(GLOBAL_CONFIG)
        exist = ldap.search_group(uid=group)

        if exist != []:
            attrs['status'] = 'already'
        else:
            try:
                ldap.addGroup(group, desc, request.user)
                add_entry_group_info(group)
                LOGGER.info("GROUP CREATED  :: Operator : %s  :: Attributes : name=%s, desc=%s ", request.user, group, desc)
                attrs['status'] = 'success'
            except:
                attrs['status'] = 'fail'
    return JsonResponse(attrs)


@login_required()
def admin_put_json(request):
    """

    :param request:
    :return:
    """
    ldap = OpenLdap(GLOBAL_CONFIG)
    data = QueryDict(request.body).dict()
    user = data['user']
    action = data['action']
    result = {}
    list_admin = []

    exist = ldap.search_user(uid=user)

    if exist == []:
        result['status'] = 'not exist'
        return JsonResponse(result)
    else:
        dict_admin = user_is_admin(request, spec='list')
        for each in dict_admin['list']:
            list_admin.append(each['uid'])

        if str(user) in list_admin and action == 'add':
            result['status'] = 'already'
            return JsonResponse(result)
        else:
            if action == 'add':
                value = True
                update_count_force(request.user, 'add')
            else:
                if str(request.user) == str(user):
                    data['status'] = "itself"
                    return JsonResponse(data)
                value = False
                update_count_force(request.user, 'remove')
            if value:
                LOGGER.info("ADMIN MODIFIED :: Operator : %s  :: Attributes : user=%s, action=promote super admin ", request.user, user)
            else:
                LOGGER.info("ADMIN MODIFIED :: Operator : %s  :: Attributes : user=%s, action=dismiss super admin ", request.user, user)
            result = update_entry_user_info(user, value)
            return JsonResponse(result)


@login_required()
def admin_get_html(request):
    """

    :param request:
    :return:
    """
    if user_is_admin(request, spec='python')['admin'] != 'False':
        return render(request, "admin.html")
    else:
        return redirect('/')


@login_required()
def user_is_group_admin(request,
                        type=None):
    """

    :param request:
    :param type:
    :return:
    """
    data = {}
    group_list = []
    user_list = []
    data['status'] = 'False'
    data['admin'] = 'False'
    user_admin = None
    # print IsAdmin.objects.filter(group__group_name="test-admin2")
    # print IsAdmin.objects.get(group=)
    # print IsAdmin.objects.filter(group__group_name="test-admin2")[0].administrators

    if request.path_info.split('/')[1] == 'groupAdmin':
        location = request.path_info.split('/')[2]
        user_admin = IsAdmin.objects.filter(group__group_name=location)

    if user_is_admin(request, spec='python')['admin'] != 'False':
        data['status'] = 'True'
        data['admin'] = ['*']

    else:
        is_admin = GroupInfo.objects.filter(administrators__username=request.user)
        if is_admin:
            for each in is_admin:
                group_list.append(str(each.group_name))
            if user_admin:
                for each in user_admin:
                    user_list.append(str(each.administrators))
                data['user'] = user_list
            data['admin'] = group_list
            data['status'] = 'True'

    if type == 'python':
        return data
    else:
        return JsonResponse(data)


@login_required()
def modify_group_admin(request,
                       user,
                       group,
                       action):
    data = {}
    data['status'] = 'false'
    if (user_is_admin(request, spec='python')['admin'] != 'False'
            or (user_is_group_admin(request, type='python')['admin'] != 'False'
            and request.META['HTTP_REFERER'].split('/')[4] in user_is_group_admin(request, type='python')['admin'])):
        if user_is_admin(request, spec='python')['admin'] == 'False'\
            and user_is_group_admin(request, type='python')['admin'] != 'False'\
            and request.META['HTTP_REFERER'].split('/')[4] in user_is_group_admin(request, type='python')['admin']\
            and str(request.user) == str(user):
            data['status'] = 'itself'
        else:
            if action == 'add':
                add_entry_is_admin(user, group)
                data['action'] = 'added'
                data['status'] = 'true'
            else:
                del_entry_is_admin(user, group)
                data['action'] = 'deleted'
                data['status'] = 'true'
    if 'action' in data:
        if data['action'] == 'added':
            LOGGER.info("GROUP MODIFIED :: Operator : %s  :: Attributes : group=%s, user=%s, action=promote group admin ", request.user, group, user)
        elif data['action'] == 'deleted':
            LOGGER.info("GROUP MODIFIED :: Operator : %s  :: Attributes : group=%s, user=%s, action=dismiss group admin ", request.user, group, user)
    return JsonResponse(data)


def login(request):
    """

    :param request:
    :return:
    """
    info = {}

    if request.user.is_authenticated():
        redirect_page = "/users/{}".format(request.user)
        return redirect(redirect_page)
    else:
        # response = urllib2.urlopen(request)
        # print response
        # print response.info()
        # print request.response.get()

        if request.method == "POST":
            user = auth.authenticate(username=request.POST['username'].lower(),
                                     password=request.POST['password'])
            if user is not None:
                redirect_page = "/users/{}".format(request.POST['username'].lower())
                auth.login(request, user)
                LOGGER.info("USER LOGIN     :: User %s is connected from %s", request.user, request.META.get('REMOTE_ADDR'))
                return HttpResponseRedirect(redirect_page)
            else:
                info['info'] = 'Your login/password are wrong'
                return render(request, "login.html", context=info)
        else:
            return render(request, "login.html")


@login_required()
def logout(request):
    """
    Logout user and redirect to login page

    :param request: HTTP request
    :return: HTTP
    """
    LOGGER.info("USER LOGOUT    :: User %s is disconnected from %s ", request.user, request.META.get('REMOTE_ADDR'))
    auth.logout(request)
    return redirect('/')


@login_required()
def user_dispatcher(request):
    """

    :param request:
    :return:
    """
    uri = request.path
    url_user = "/users/{}".format(request.user)

    if uri != url_user\
            and 'dn' not in request.GET:
        return HttpResponseRedirect(url_user)
    else:
        if request.method == 'GET'\
                and 'format' in request.GET\
                and request.GET['format'] == 'json':
            return user_get_json(request)
        elif request.method == 'GET':
            return render(request, 'user_get_html.html')


@login_required()
def groups_dispatcher(request):
    """

    :param request:
    :return:
    """
    if (user_is_admin(request, spec='python')['admin'] != 'False'
            or (user_is_group_admin(request, type='python')['admin'] != 'False'
                and (request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin']
                    or (len(request.META['HTTP_REFERER'].split('/')) == 5
                        and request.META['HTTP_REFERER'].split('/')[4] in user_is_group_admin(request, type='python')['admin'])))):
        if request.method == 'PUT':
            data = QueryDict(request.body).dict()
            user = data['user']
            group = data['group']
            action = data['action']
            return modify_group_admin(request, user, group, action)
        elif request.method == 'GET'\
                and 'format' in request.GET\
                and request.GET['format'] == 'json':
            return groups_get_json(request, spec='all')
        else:
            return groups_get_html(request)

    elif request.method == 'GET'\
            and 'format' in request.GET\
            and request.GET['format'] == 'json'\
            and user_is_group_admin(request, type='python')['admin'] != 'False':
            # and request.path in user_is_group_admin(request, type='python')['admin']:

        return groups_get_json(request)
    elif request.method == 'GET'\
            and user_is_group_admin(request, type='python')['admin'] != 'False':
        return groups_get_html(request)
    else:
        return redirect('/')


@login_required()
def group_dispatcher(request):
    """

    :param request:
    :return:
    """
    if request.method == 'GET'\
            and 'format' in request.GET\
            and 'email' in request.GET\
            and request.GET['format'] == 'json'\
            and request.GET['email'] == 'bar'\
            and ((user_is_group_admin(request, type='python')['admin'] != 'False'
                and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin'])
                or user_is_admin(request, spec='python')['admin'] != 'False'):
        return user_get_json(request)

    elif request.method == 'GET'\
            and 'format' in request.GET\
            and request.GET['format'] == 'json'\
            and ((user_is_group_admin(request, type='python')['admin'] != 'False'
            and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin'])
                or user_is_admin(request, spec='python')['admin'] != 'False'):
        return group_get_json(request)

    elif request.method == 'GET'\
            and ((user_is_group_admin(request, type='python')['admin'] != 'False'
            and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin'])
                or user_is_admin(request, spec='python')['admin'] != 'False'):
        return group_get_html(request)

    elif request.method == 'GET'\
            and 'admin' in request.GET\
            and ((user_is_group_admin(request, type='python')['admin'] != 'False'
            and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin'])
                or user_is_admin(request, spec='python')['admin'] != 'False'):
        return group_get_json(request)

    elif request.method == 'DEL'\
            and ((user_is_group_admin(request, type='python')['admin'] != 'False'
            and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin'])
                or user_is_admin(request, spec='python')['admin'] != 'False'):
        return group_del_json(request)

    elif request.method == 'PUT'\
        and ((user_is_group_admin(request, type='python')['admin'] != 'False'
        and request.path_info.split('/')[2] in user_is_group_admin(request, type='python')['admin'])
            or user_is_admin(request, spec='python')['admin'] != 'False'):
        return group_put_json(request)

    else:
        return redirect('/')


@login_required()
def group_put_json(request):
    """

    :param request:
    :return:
    """
    status = "False"
    ldap = OpenLdap(GLOBAL_CONFIG)
    data = QueryDict(request.body).dict()
    user = data['user']
    group = request.path_info.split('/')[2]

    try:
        dn_user = ldap.search_user(uid=user)[0][0]
        dn_group = ldap.search_group(group)[0][0]
        info = ldap.add_user_from_group(dn_user, dn_group)

        if info:
            status = "True"
            if user_is_admin(request, spec='python')['admin'] != 'False':
                update_count_force(request.user, 'add')
            else:
                status = "False"
            LOGGER.info("GROUP MODIFIED :: Operator : %s  :: Attributes : group=%s, user=%s, action=member added", request.user, group, user)
        else:
            status = "already"
    except:
        status = "not exist"

    data['status'] = status
    return JsonResponse(data)


@login_required()
def group_del_json(request):
    """

    :param request:
    :return:
    """
    ldap = OpenLdap(GLOBAL_CONFIG)
    data = QueryDict(request.body).dict()
    user = data['user']

    if str(request.user) == str(user):
        data['status'] = 'itself'
        return JsonResponse(data)
    else:
        group = request.path_info.split('/')[2]
        dn_user = ldap.search_user(uid=user)[0][0]
        dn_group = ldap.search_group(group)[0][0]
        info = ldap.delete_user_from_group(dn_user, dn_group)

        if info:
            status = "True"
            if user_is_admin(request, spec='python')['admin'] != 'False':
                update_count_force(request.user, 'remove')
            try:
                del_entry_is_admin(user, group)
            except:
                pass
            LOGGER.info("GROUP MODIFIED :: Operator : %s  :: Attributes : group=%s, user=%s, action=member deleted", request.user, group, user)
        else:
            status = "False"
        data['status'] = status
        return JsonResponse(data)


@login_required()
def group_get_json(request):
    """

    :param request:
    :return:
    """
    data = {}
    ldap = OpenLdap(GLOBAL_CONFIG)
    user_list = []

    if 'admin' in request.GET:
        location = request.path_info.split('/')[2]
        user_admin = IsAdmin.objects.filter(group__group_name=location)
        if user_admin:
            for each in user_admin:
                user_list.append(str(each.administrators))
            data['admin'] = user_list

    else:
        attrs = ldap.search_group(request.path_info.split('/')[2])
        data['attrs'] = {}

        for key, value in attrs:
            for each in value:
                data['attrs'][each] = value[each]

        if data['attrs']['uniqueMember'] is not '':
            members = user_get_json(request, spec=data['attrs']['uniqueMember'])
            data['members'] = members['members']
            data['admin'] = members['admin']
    return JsonResponse(data)


@login_required()
def group_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'group_get_html.html')


@login_required()
def user_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'user_get_html.html')


@login_required()
def user_get_json(request,
                  spec=None):
    """

    :param request:
    :return:
    """
    data = {}
    ldap = OpenLdap(GLOBAL_CONFIG)
    data['attrs'] = {}
    data['users'] = {}
    members = []
    final_list = []
    final_dict = {}
    admin_list = []

    if spec is not None:
        for uid in spec:
            attrs = ldap.search_user(attributes=str(uid).split('=')[1].split(',')[0])
            if attrs != []:
                members.append(attrs[0][1])
        for each in members:
            tmp = each
            for key in tmp:
                tmp[key] = tmp[key][0]
            tmp['icon'] = ''
            tmp['admin'] = ''
            final_list.append(tmp)

        location = request.path_info.split('/')[2]
        user_admin = IsAdmin.objects.filter(group__group_name=location)
        if user_admin:
            for each in user_admin:
                admin_list.append(str(each.administrators))
        data['admin'] = admin_list

        data['members'] = final_list
        return data
    elif 'email' in request.GET:
        users = ldap.search_user(uid="foo", mail="bar")
        for each in users:
            members.append(each[1])
        for each in members:
            tmp = each
            final_dict[tmp['uid'][0]] = tmp['mail'][0]
        data['users'] = final_dict
        return JsonResponse(data)

    else:
        attrs = ldap.search_user(attributes=request.user)

        for key, value in attrs:
            for each in value:
                data['attrs'][each] = value[each]
    return JsonResponse(data)


def home_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'home_get_html.html')


@login_required()
def groups_get_html(request):
    """

    :param request:
    :return:
    """
    data = user_is_group_admin(request, type='python')
    if data['status'] != 'True':
        return redirect('/')
    else:
        return render(request, 'groups_get_html.html')


@login_required()
def groups_get_json(request,
                    spec=None):
    """

    :param request:
    :param spec:
    :return:
    """
    data = {}
    groups = []

    if spec is not None:
        ldap = OpenLdap(GLOBAL_CONFIG)
        groups_value = ldap.search_groups()
        for each in groups_value:
            groups.append(each[1]['cn'][0])
    else:
        is_admin = user_is_group_admin(request, type='python')
        for each in is_admin['admin']:
            groups.append(each)
    data['groups'] = groups
    return JsonResponse(data)


def policies_get_html(request):
    """

    :param request:
    :return:
    """
    return render(request, 'policies_get_html.html')


def register_dispatcher(request):
    attributes = {}
    if 'format' in request.GET:
        if 'adduser' in request.GET:
            attributes = QueryDict(request.body).dict()
            add_user(request, attributes)
            return JsonResponse(attributes)
        elif 'cert' in request.GET:
            if 'SSL_CLIENT_S_DN' in request.META:
                attributes['DN'] = request.META['SSL_CLIENT_S_DN']
            return JsonResponse(attributes)
    else:
        return render(request, 'register_get_html.html')


def attributes_dispatcher(request):
    attributes = {}
    if 'password' in request.GET:
        password = request.GET['password']
        attributes = check_password_constraints(password)
        return JsonResponse(attributes)

    if 'checkPassword' in request.GET:
        ldap = OpenLdap(GLOBAL_CONFIG)
        password = unicode(request.GET['checkPassword']).encode(encoding='utf-8')
        uid = str(request.user)
        userPassword = ldap.search_user(password=uid)

        userPassword = userPassword[0][1]['userPassword'][0]
        checked = check_password(userPassword, password)

        if checked:
            attributes['status'] = 'success'
        else:
            attributes['status'] = 'fail'
        return JsonResponse(attributes)

    if 'changePassword' in request.GET:
        info = {}
        attributes = QueryDict(request.body).dict()
        ldap = OpenLdap(GLOBAL_CONFIG)
        uid = str(request.user)
        password = encode_password(unicode(attributes['changePassword'])
                                   .encode(encoding='utf-8'))
        try:
            attrs = ldap.change_user_password(uid, password)
            LOGGER.info("USER MODIFIED  :: username=%s, action=password changed", request.user)
            return JsonResponse(attrs)
        except:
            info['info'] = 'Fail to change your password.'
            return render(request, 'error_get_html.html', context=info)
        # return render(request, 'home_get_html.html')

    ### TEST ###
    elif 'passwords' in request.GET:
        password = request.GET['passwords']
        attributes['password'] = encode_password(password)
        print type(password)
        print password
        print type(attributes['password'])
        print attributes['password']
        # return JsonResponse(attributes)
        return render(request, 'users_get_html.html')
    ### END ###

    elif 'uid' in request.GET:
        ldap = OpenLdap(GLOBAL_CONFIG)
        uid = normalize_string(request.GET['uid'])
        checked = ldap.search_user(uid=uid)
        attributes['uid'] = uid

        if checked:
            attributes['status'] = 'fail'
        else:
            attributes['status'] = 'success'
        return JsonResponse(attributes)

    elif 'firstname' in request.GET:
        firstname = normalize_string(request.GET['firstname'], option='name')
        lastname = normalize_string(request.GET['lastname'], option='name')
        attributes['firstname'] = firstname
        attributes['lastname'] = lastname
        return JsonResponse(attributes)

    elif 'mail' in request.GET:
        ldap = OpenLdap(GLOBAL_CONFIG)
        mail = request.GET['mail']
        checked = ldap.search_user(mail=mail)

        if checked:
            attributes['status'] = 'fail'
        else:
            attributes['status'] = 'success'
        return JsonResponse(attributes)

    elif 'project' in request.GET:
        project = normalize_string(request.GET['project'])
        attributes['project'] = project
        return JsonResponse(attributes)


def add_user(request,
             attributes):
    GLOBAL_CONFIG['project'] = ''
    ldap = OpenLdap(GLOBAL_CONFIG)
    username = str(attributes['username'])
    email = str(attributes['email'])
    firstname = str(attributes['firstname'])
    lastname = str(attributes['lastname'])
    x500dn = str(attributes['x500dn'])
    GLOBAL_CONFIG['project'] = str(attributes['project'])
    password = encode_password(unicode(attributes['password']).encode(encoding='utf-8'))

    try:
        ldap.add_user(username, email, firstname, lastname, x500dn, password)
        LOGGER.info("USER CREATED   :: Operator : %s  :: Attributes : username=%s, firstname=%s, lastname=%s, email=%s ", request.user, username, firstname, lastname, email)
    except InvalidX500DN:
        exit(1)
    send_mail(username, firstname, lastname, email, '', '', 'add')


def activate_user(request):
    uuid = request.path.split('/action/')
    uuid.pop(0)
    uuid = str(uuid[0])
    ldap = OpenLdap(GLOBAL_CONFIG)
    info = {}
    try:
        attrs = ldap.enable_user(uuid)
        send_mail(attrs['username'], attrs['firstname'], attrs['lastname'],
                  attrs['mail'], GLOBAL_CONFIG['project'],
                  # 'marchal@lal.in2p3.fr', 'enable')
                  GLOBAL_CONFIG['admin'], 'enable')
        LOGGER.info("USER MODIFIED  :: user=%s, action=activated", attrs['username'])
    except:
        info['info'] = 'Your account is already enable or the url is not ' \
                          'valid, please check your mailbox.'
        return render(request, 'error_get_html.html', context=info)
    return render(request, 'home_get_html.html')
