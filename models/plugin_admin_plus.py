# -*- coding: utf-8 -*-

###############################################################################
# Plugin - Admin Plus
# Copyright (C) 2014  Samuel Bonilla <pythonners@gmail.com>

# License: LGPLv3 (http://www.gnu.org/licenses/lgpl.html)
###############################################################################

__author__ = 'Samuel bonilla'

import os
import copy
from gluon.storage import Settings

global_env = copy.copy(globals())


def get_databases():
    ''' global variables that are instance of DAL

        --- This function returns a dictionary
            with the connections to databases'''

    dbs = {}
    for (key, value) in global_env.items():
        cond = isinstance(value, DAL)
        if cond:
            dbs[key] = value
    return dbs


databases = get_databases()
db = databases.values()[0]  # # Take only one database for now.
tables = sorted(db.tables)
settings = Settings()


#-------- Role configuration  ---------------

settings.superuser_role = "plugin_admin_plus_superuser"
settings.reader_role    = "plugin_admin_plus_reader",
settings.editor_role    = "plugin_admin_plus_editor"
settings.creator_role   = "plugin_admin_plus_creator"
settings.deleter_role   = "plugin_admin_plus_deleter"

settings.roles = roles = {}
roles[settings.superuser_role] = 'Super Users can create, read, update and delete records in all tables including Auth tables.'
roles[settings.reader_role] = 'Readers can read records in all tables.'
roles[settings.editor_role] = 'Editors can edit records in all tables.'
roles[settings.creator_role] = 'Creators can create records in all tables.'
roles[settings.deleter_role] = 'deleters can delete records in all tables.'


#------------- plugin configuration ------------

from gluon.tools import PluginManager
plugins = PluginManager('admin_plus', **settings)


if request.controller == 'plugin_admin_plus':
    auth.settings.controller = 'plugin_admin_plus'
    auth.settings.login_url = URL(c='plugin_admin_plus', f='user', args='login')
    auth.settings.on_failed_authentication = URL(c='plugin_admin_plus', f='user', args='login')
    auth.settings.on_failed_authorization = URL(c='plugin_admin_plus', f='user', args='not_authorized')
    auth.settings.login_next = URL(c='plugin_admin_plus', f='index')
    auth.settings.logout_next = URL(c='plugin_admin_plus', f='index')
    auth.settings.profile_next = URL(c='plugin_admin_plus', f='index')


# ---------- Auth Tables ------------

auth_tables = [str(auth.settings.table_user),
               str(auth.settings.table_group),
               str(auth.settings.table_membership),
               str(auth.settings.table_permission),
               str(auth.settings.table_event),
               str(auth.settings.table_cas)
              ]

auth.messages.access_denied = None

def is_auth_table(table_name):
    return str(table_name) in auth_tables


#--------- Groups and permissions to enable the plugin ----------

def record_exists(table, field, value):
    table = str(table)
    field = str(fiel)
    return db(db[table][field]==value).select().first() is not None

def get_or_create_group(role, description):
    group = db(auth.settings.table_group.role == role).select().first()
    if not group:
        group_id = auth.add_group(role=role, description=description)
        group = auth.settings.table_group(group_id)
    return group

def get_or_create_permission(group_id, name, table_name):
    query = auth.settings.table_permission.group_id == group_id
    query &= (auth.settings.table_permission.name == name)
    query &= (auth.settings.table_permission.table_name == table_name)
    permission = db(query).select().first()
    if not permission:
        permission_id = auth.add_permission(group_id, name, table_name)
        permission = auth.settings.table_permission(permission)
    return permission


#----------- Functions that uses the controller ------------------

def create_roles():
    for role in plugins.admin_plus.roles:
        group = get_or_create_group(role, plugins.admin_plus.roles[role])

        for table in tables:
            if table not in auth_tables:
                if role == plugins.admin_plus.creator_role:
                    get_or_create_permission(group.id, 'create', table)
                elif role == plugins.admin_plus.reader_role:
                    get_or_create_permission(group.id, 'read', table)
                elif role == plugins.admin_plus.editor_role:
                    get_or_create_permission(group.id, 'update', table)
                elif role == plugins.admin_plus.deleter_role:
                    get_or_create_permission(group.id, 'delete', table)

            # super users can access all tables
            if role == plugins.admin_plus.superuser_role:
                    get_or_create_permission(group.id, 'create', table)
                    get_or_create_permission(group.id, 'read', table)
                    get_or_create_permission(group.id, 'update', table)
                    get_or_create_permission(group.id, 'delete', table)


def validate(table_name, id=None):
    """
    Verifies that table and id exists in db
    and returns corresponding Table and Row objects.
    """

    if is_auth_table(table_name) and not auth.has_membership(role=plugins.admin_plus.superuser_role):
        redirect(auth.settings.on_failed_authorization)

    table_name in tables or error()
    table = db[table_name]

    if id:
        assert int(id), error()
        id = int(id)
        row = table[id] or error()
    else:
        row = None

    return table, row


def error():
    raise HTTP(404)


#------------------- page -------------------------

def pretty(s):
    s = str(s).replace('_',' ').title()
    if s.endswith(' Id'):
        s = s.replace(' Id', '')
    return s

def plural(name):
    """Minimal and stupid"""
    name = pretty(name)

    if name.endswith('s'):
        return name
    else:
        return name + 's'

def singular(name):
    """Minimal and stupid"""
    name = pretty(name)

    if name.endswith('s'):
        return name[:-1]
    else:
        return name



def refactorizar_campos(table):
    """ customize fields

        campo is field
    """

    if table:
        filas = table.fields
        for fila in filas[1:]: # no id
            campo = table[fila]
            if campo.type == 'string':
                campo.widget = lambda campo, valor: SQLFORM.widgets.string.widget(campo, valor,\
                                                    _type="text", _id="text1",  _class="form-control", \
                                                   _style="margin-bottom: 15px;")

            elif campo.type == 'text':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.text.widget(campo, valor,\
                                                    _id="text4", _class="form-control", \
                                                   _style="margin-bottom: 15px;")

            elif campo.type == 'password':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.password.widget(campo, valor,\
                                    _class="form-control", _type="password", _id="pass1", \
                                     _style="margin-bottom: 15px;")

            elif campo.type == 'boolean':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.boolean.widget(campo, valor,\
                                    _type="checkbox", _id="agree", _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type == 'datetime':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.string.widget(campo, valor,\
                                    _type="text", _id="tiempos", _class="form-control ", \
                                     _style="margin-bottom: 15px;")

            elif campo.type == 'date':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.string.widget(campo, valor,\
                                    _type="text", _id="date", _class="date form-control ", \
                                     _style="margin-bottom: 15px;")

            elif campo.type == 'time':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.time.widget(campo, valor,\
                                    _type="time", _id="time", _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type == 'integer':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.integer.widget(campo, valor,\
                                     _id="spin1", _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type == 'double':
                 campo.widget = lambda campo, valor: SQLFORM.widgets.double.widget(campo, valor,\
                                     _id="spin2", _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type.startswith('reference'):
                 campo.widget = lambda campo, valor: SQLFORM.widgets.options.widget(campo, valor,\
                                     _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type.startswith('list:string'):
                 campo.widget = lambda campo, valor: SQLFORM.widgets.string.widget(campo, valor,\
                                      _id='tags', _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type.startswith('list:integer'):
                 campo.widget = lambda campo, valor: SQLFORM.widgets.string.widget(campo, valor,\
                                     _id='tags', _class="form-control", \
                                     _style="margin-bottom: 15px;")

            elif campo.type.startswith('list:reference'):
                 campo.widget = lambda campo, valor: SQLFORM.widgets.checkboxes.widget(campo, valor,\
                                     _id="ch2", _class="checkbox anim-checkbox success", \
                                     _style="margin-bottom: 15px; overflow: auto; height: 90px; padding-left: 40px;")



#--------------- pagination --------------------------

def get_pages_list(current_page, number_of_pages):
    """Returns the list of page numbers for pagination
    """
    # taken from http://pypi.python.org/pypi/django-pure-pagination

    PAGE_RANGE_DISPLAYED = 8
    MARGIN_PAGES_DISPLAYED = 2

    result = []
    if number_of_pages <= PAGE_RANGE_DISPLAYED:
        return range(1, number_of_pages+1)


    left_side = PAGE_RANGE_DISPLAYED/2
    right_side = PAGE_RANGE_DISPLAYED - left_side

    if current_page > number_of_pages - PAGE_RANGE_DISPLAYED/2:
        right_side = number_of_pages - current_page
        left_side = PAGE_RANGE_DISPLAYED - right_side
    elif current_page < PAGE_RANGE_DISPLAYED/2:
        left_side = current_page
        right_side = PAGE_RANGE_DISPLAYED - left_side

    for page in range(1, number_of_pages+1):
        if page <= MARGIN_PAGES_DISPLAYED:
            result.append(page)
            continue
        if page > number_of_pages - MARGIN_PAGES_DISPLAYED:
            result.append(page)
            continue
        if (page >= current_page - left_side) and (page <= current_page + right_side):
            result.append(page)
            continue
        if result[-1]:
            result.append(None)

    return result


#------------ -------------- -------------- --------------

def sidebar_tables():
    '''Default Menu'''
    t = []
    for table in tables:
        if auth.has_permission('read', table):
            li = LI(A(I(_class="fa fa-angle-right"), " "+plural(table), _href=URL('list', args=table)),
                    _class="")

            if table in request.args:
                li['_class'] = ""
            t.append(li)
    return t





