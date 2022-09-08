#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

import os
import hashlib
import unicodedata
import re
import logging
from logging.handlers import RotatingFileHandler
# from base64 import urlsafe_b64encode as encode
# from base64 import urlsafe_b64decode as decode
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import uuid
from models import UserActivation, UserInfo, GroupInfo, IsAdmin
from datetime import datetime

LOGGER = logging.getLogger("registration")

# def create_logger(mode,
#                   stream_level=logging.INFO,
#                   file_level=logging.DEBUG):
#     """
#     Create a logger according to the given level
#     :param mode:
#     :param stream_level:
#     :param file_level:
#     :return:
#     """
#     logger = logging.getLogger("registration")
#     logger.setLevel(logging.DEBUG)
#
#     # Use rsyslog to send logs to others
#     # handler = logging.handlers.SysLogHandler(address="/dev/log")
#     formatter = logging.Formatter(
#         '%(asctime)s :: %(levelname)s :: %(message)s'
#     )
#
#     if mode == 'both':
#         # Fichier en mode 'append', avec 1 backup et une taille max de 1Mo
#         file_handler = RotatingFileHandler('/var/log/registration/registration.log',
#                                            'a',
#                                            1000000,
#                                            1)
#
#         file_handler.setLevel(file_level)
#         file_handler.setFormatter(formatter)
#         logger.addHandler(file_handler)
#
#     # rsyslog
#     # handler.formatter = formatter
#     # logger.addHandler(handler)
#     #
#     # stream_handler = logging.StreamHandler()
#     # stream_handler.setLevel(stream_level)
#     # logger.addHandler(stream_handler)
#
#     return logger

# def encode_password(password):
#     salt = os.urandom(4)
#     h = hashlib.sha1(password)
#     h.update(salt)
#     return '{SSHA}' + encode(h.digest() + salt)

def encode_password(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer
    :param password:
    """
    salt = os.urandom(4)

    # hash the password and append the salt
    sha = hashlib.sha1(password)
    sha.update(salt)

    # create a base64 encoded string of the concatenated digest + salt
    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()

    # now tag the digest above with the {SSHA} tag
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)

    return tagged_digest_salt


def check_password(tagged_digest_salt, password):
    """
    Checks the OpenLDAP tagged digest against the given password
    :param tagged_digest_salt:
    :param password:
    """
    # the entire payload is base64-encoded
    assert tagged_digest_salt.startswith('{SSHA}')

    # strip off the hash label
    digest_salt_b64 = tagged_digest_salt[6:]

    # the password+salt buffer is also base64-encoded.  decode and split the
    # digest and salt
    digest_salt = digest_salt_b64.decode('base64')
    digest = digest_salt[:20]
    salt = digest_salt[20:]

    sha = hashlib.sha1(password)
    sha.update(salt)

    return digest == sha.digest()


# def check_password(challenge_password, password):
#     challenge_bytes = decode(challenge_password[6:])
#     digest = challenge_bytes[:20]
#     salt = challenge_bytes[20:]
#     hr = hashlib.sha1(password)
#     hr.update(salt)
#     return digest == hr.digest()


def check_password_constraints(password):
    """

    :param password:
    :return:
    """
    attributes = {}
    # password = request.GET['password']
    constraint = {'lower': False,
                  'upper': False,
                  'spe': False,
                  'number': False}
    index = 0
    total = 0
    taille = len(password)
    spe = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+',
           '{', '}', '"', ':', ';', '\', ''', '[', ']', '<', '>']

    while index < taille:
        var = password[index]
        if var.islower():
            constraint['lower'] = True
        if var.isupper():
            constraint['upper'] = True
        if var in spe:
            constraint['spe'] = True
        if var.isdigit():
            constraint['number'] = True
        index += 1

    if constraint['lower']:
        total += 1
    if constraint['upper']:
        total += 1
    if constraint['spe']:
        total += 1
    if constraint['number']:
        total += 1

    if len(password) < 8:
        attributes['check'] = 'character'
    elif total < 3:
        attributes['check'] = 'require'
    elif len(password) >= 8 and total >= 3:
        attributes['check'] = 'success'
    else:
        attributes['check'] = 'error'
    return attributes


def normalize_string(string,
                     option=None):
    """

    :param string:
    :param option:
    :return:
    """
    if option is None or option == 'username':
        return re.sub(r'[\W_]', '',
                      unicodedata.normalize('NFKD', string)
                      .encode('ASCII', 'ignore').lower())
    elif option == 'name':
        return re.sub(r'[\s]', '-',
                      re.sub(r'[^a-zA-Z, -]', '',
                             unicodedata.normalize('NFKD', string)
                             .encode('ASCII', 'ignore').lower()))


def send_mail(username,
              firstname,
              lastname,
              user_email,
              project,
              admin_mail,
              action):
    """

    :param username:
    :param firstname:
    :param lastname:
    :param user_email:
    :param admin_mail:
    :param action:
    :return:
    """
    message = ''
    all_rcpt = ''
    header = MIMEMultipart()
    header['From'] = 'no-reply@lal.in2p3.fr'
    header['To'] = user_email
    header['Subject'] = 'OpenStack Registration Message'

    if action == 'add':
        all_rcpt = user_email
        random_string = uuid.uuid4()
        link = "http://134.158.76.228:8000/action/{}".format(random_string)
        message = "Dear {} {}, \n\nYou just created an account on OpenStack@lal.\n" \
                  "Please follow the link to activate your account: \n{}\n\n" \
                  "You can have access to your profile on the registration " \
                  "website but YOU ARE NOT ABLE TO AUTHENTICATE ON THE CLOUD " \
                  "UNTIL ENABLED." \
                  "\n\nDon't reply at this email.\n" \
                  "Support : https://cloud-support.lal.in2p3.fr/"\
                  .format(firstname,
                          lastname,
                          link)
        add_entry_user_activation(random_string, username)

    elif action == 'enable':
        all_rcpt = str(admin_mail).split(',') + [user_email]
        header['Bcc'] = str(admin_mail)
        message = "Dear {} {}, \n\nYour account have been successfully " \
                  "activated.\n" \
                  "You still must belong to a project to use the platform.\n" \
                  "Please contact your project administrator to be allowed " \
                  "to connect to https://keystone.lal.in2p3.fr. \n\n" \
                  "Your domain is 'stratuslab'.\n" \
                  "Your Username is '{}'.\n" \
                  "Project you want to be added : {}\n" \
                  "\n\nDon't reply at this email.\n" \
                  "Support : https://cloud-support.lal.in2p3.fr/"\
                  .format(firstname,
                          lastname,
                          username,
                          project)
        add_entry_user_info(username, datetime.now())

    header.attach(MIMEText(message))
    mail_server = smtplib.SMTP('smtp.lal.in2p3.fr', 25)
    # replace marchal@ by all_rcpt
    # mail_server.sendmail('no-reply@lal.in2p3.fr', 'marchal@lal.in2p3.fr',
    mail_server.sendmail('no-reply@lal.in2p3.fr', all_rcpt,
                         header.as_string())

    mail_server.quit()


def add_entry_user_activation(random_string,
                              user):

    new_user = UserActivation(link=random_string, username=user)
    new_user.save()


def add_entry_user_info(user,
                        date):
    new_user = UserInfo(username=user, last_agreement=date, enabled=True)
    new_user.save()


def add_entry_group_info(group):
    new_group = GroupInfo(group_name=group)
    new_group.save()


def add_entry_is_admin(user,
                      group):
    user_id = UserInfo.objects.filter(username=user)[0].id
    exist_user = UserInfo.objects.get(id=user_id)
    group_id = GroupInfo.objects.filter(group_name=group)[0].id
    exist_group = GroupInfo.objects.get(id=group_id)
    new_admin = IsAdmin(administrators=exist_user, group=exist_group)
    new_admin.save()


def del_entry_is_admin(user,
                       group):
    user_id = UserInfo.objects.filter(username=user)[0].id
    exist_user = UserInfo.objects.get(id=user_id)
    group_id = GroupInfo.objects.filter(group_name=group)[0].id
    exist_group = GroupInfo.objects.get(id=group_id)
    admin = IsAdmin.objects.filter(administrators=exist_user, group=exist_group)
    admin.delete()


def update_entry_user_info(user,
                           value):
    data = {}
    try:
        existing_user = UserInfo.objects.filter(username=user)
        # existing_user[0].admin = value
        existing_user.update(admin=value)
        data['status'] = 'True'
    except:
        data['status'] = 'False'
    return data

def update_count_force(user,
                       action):
    try:
        existing_user = UserInfo.objects.filter(username=user)
        if action == 'add':
            value = existing_user[0].countForce + 1
        else:
            value = existing_user[0].countForce - 1
        existing_user.update(countForce=value)
    except:
        pass
