import ldap3
from ldap3.utils import dn
from ldap3.core import exceptions


class LDAP(object):
    def __init__(self, host, user, password, search_base, attributes, groups, connect_timeout=60):
        self.host = host
        self.user = user
        self.password = password
        self.search_base = search_base
        self.attributes = attributes
        self.groups = groups

        self._server = ldap3.Server(self.host, get_info=ldap3.NONE, connect_timeout=connect_timeout)
        self._connection = ldap3.Connection(self._server, self.user, self.password, read_only=True)

    @staticmethod
    def _last_cn(distinguished_name):
        parsed = dn.parse_dn(distinguished_name)
        filtered = [value for rdn, value, _ in parsed if rdn == 'CN']
        if filtered:
            return filtered[0]

    def check_connection(self):
        try:
            with self._connection:
                return True
        except exceptions.LDAPBindError:
            raise RuntimeError('Incorrect user or password')
        except exceptions.LDAPSocketOpenError:
            raise RuntimeError('Connection timeout')

    def check_password(self, distinguished_name, password):
        try:
            connection = ldap3.Connection(self._server, distinguished_name, password, auto_bind=True)
            connection.unbind()
            return True
        except exceptions.LDAPBindError:
            return False

    def account_info(self, account_name, skip_member_check=False, additional_attributes=None):
        if additional_attributes is None:
            additional_attributes = []

        with self._connection as connection:
            connection.search(self.search_base,
                              '(&(objectClass=user)(sAMAccountName=%s))' % account_name,
                              attributes=self.attributes + additional_attributes,
                              size_limit=1)
            if connection.entries:
                entry = connection.entries[0]
                attributes_as_dict = entry.entry_attributes_as_dict
                attributes_as_dict['distinguishedName'] = entry.entry_dn

                if 'memberOf' in attributes_as_dict:
                    member_of = [self._last_cn(dn_) for dn_ in attributes_as_dict['memberOf']]
                    member_of = [group for group in member_of if group in self.groups]
                    attributes_as_dict['memberOf'] = member_of
                else:
                    member_of = list()
                    for group, dns in self.group_to_dns():
                        if attributes_as_dict['distinguishedName'] in dns:
                            member_of.append(group)
                    attributes_as_dict['memberOf'] = member_of
                if not skip_member_check and not attributes_as_dict['memberOf']:
                    return

                for attribute, values in attributes_as_dict.items():
                    if attribute != 'memberOf' and type(values) == list:
                        if len(values) == 0:
                            attributes_as_dict[attribute] = None
                        if len(values) == 1:
                            attributes_as_dict[attribute] = values[0]

                attributes_as_dict['name'] = self._last_cn(attributes_as_dict['distinguishedName'])
                attributes_as_dict['account_name'] = account_name
                attributes_as_dict['groups'] = attributes_as_dict.pop('memberOf')
                if isinstance(attributes_as_dict['groups'], list):
                    attributes_as_dict['groups'].append(attributes_as_dict['department'])
                else:
                    attributes_as_dict['groups'] = [attributes_as_dict['department']]
                return attributes_as_dict

    def group_to_dns(self):
        group_to_dns_ = {group: list() for group in self.groups}
        with self._connection as connection:
            for group in self.groups:
                connection.search(self.search_base,
                                  '(&(objectClass=Group)(cn=%s))' % group,
                                  attributes=['member'])
                if connection.entries and 'member' in connection.entries[0]:
                    group_to_dns_[group] = connection.entries[0]['member'].values
        return group_to_dns_
