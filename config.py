import os
hq_ldap_host = os.getenv('HQ_LDAP_HOST', "172.27.126.11:389")
hq_ldap_user = os.getenv('HQ_LDAP_USER', "RPA_SUPPORT")
hq_ldap_password = os.getenv('HQ_LDAP_PASSWORD', "Ca0Dgj0EERzx8EWJV22l")
hq_ldap_search_base = 'DC=halykbank,DC=nb'
hq_ldap_attributes = ['distinguishedName', 'memberOf', 'department']
hq_ldap_groups = ['Управление RPA',
                  'УТВС',
                  'Упр. тестирования вспомогат. систем',
                  'Управление администрирования розничных займов',
                  'Управление координации администрирования займов МСБ',
                  'Управление администрирования банковских операций']