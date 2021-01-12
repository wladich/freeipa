# Copyright (C) 2019  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import textwrap

import pytest

from ipaplatform.constants import constants as platformconstants
from ipaplatform.paths import paths

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipapython.dn import DN


class BaseTestTrust(IntegrationTest):
    topology = 'line'
    num_ad_domains = 1

    upn_suffix = 'UPNsuffix.com'
    upn_username = 'upnuser'
    upn_name = 'UPN User'
    upn_principal = '{}@{}'.format(upn_username, upn_suffix)
    upn_password = 'Secret123456'

    shared_secret = 'qwertyuiopQq!1'
    default_shell = platformconstants.DEFAULT_SHELL

    @classmethod
    def install(cls, mh):
        if not cls.master.transport.file_exists('/usr/bin/rpcclient'):
            raise pytest.skip("Package samba-client not available "
                              "on {}".format(cls.master.hostname))
        super(BaseTestTrust, cls).install(mh)
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        tasks.install_adtrust(cls.master)
        cls.check_sid_generation()
        tasks.sync_time(cls.master, cls.ad)

        # values used in workaround for
        # https://bugzilla.redhat.com/show_bug.cgi?id=1711958
        cls.srv_gc_record_name = \
            '_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs'
        cls.srv_gc_record_value = '0 100 389 {}.'.format(cls.master.hostname)

    @classmethod
    def check_sid_generation(cls):
        command = ['ipa', 'user-show', 'admin', '--all', '--raw']

        # TODO: remove duplicate definition and import from common module
        _sid_identifier_authority = '(0x[0-9a-f]{1,12}|[0-9]{1,10})'
        sid_regex = 'S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s'\
                    % dict(idauth=_sid_identifier_authority)
        stdout_re = re.escape('  ipaNTSecurityIdentifier: ') + sid_regex

        tasks.run_repeatedly(cls.master, command,
                             test=lambda x: re.search(stdout_re, x))

    def check_trustdomains(self, realm, expected_ad_domains):
        """Check that ipa trustdomain-find lists all expected domains"""
        result = self.master.run_command(['ipa', 'trustdomain-find', realm])
        for domain in expected_ad_domains:
            expected_text = 'Domain name: %s\n' % domain
            assert expected_text in result.stdout_text
        expected_text = ("Number of entries returned %s\n" %
                         len(expected_ad_domains))
        assert expected_text in result.stdout_text

    def check_range_properties(self, realm, expected_type, expected_size):
        """Check the properties of the created range"""
        range_name = realm.upper() + '_id_range'
        result = self.master.run_command(['ipa', 'idrange-show', range_name,
                                          '--all', '--raw'])
        expected_text = 'ipaidrangesize: %s\n' % expected_size
        assert expected_text in result.stdout_text
        expected_text = 'iparangetype: %s\n' % expected_type
        assert expected_text in result.stdout_text

    def remove_trust(self, ad):
        tasks.remove_trust_with_ad(self.master, ad.domain.name)
        tasks.clear_sssd_cache(self.master)


class TestTrust(BaseTestTrust):

    # Tests for non-posix AD trust

    def test_establish_nonposix_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

    def test_subordinate_suffix(self):
        """Test subordinate UPN suffixes routing.

        Given an AD domain ad.test with additional UPN suffix suffix.ad.test
        check that requests from IPA for suffix.ad.test
        are properly routed to ad.test.

        This is a regression test for https://pagure.io/freeipa/issue/8554
        """

        # Create subordinate UPN suffix
        subordinate_suffix = 'test_subdomain.' + self.ad_domain
        self.ad.run_command([
            'powershell', '-c',
            'Set-ADForest -Identity {} -UPNSuffixes @{{add="{}"}}'.format(
                self.ad_domain, subordinate_suffix)])
        try:
            # Verify UPN suffix is created
            cmd = ('Get-ADForest -Identity {} '
                   '| Select-Object -Property UPNSuffixes'
                   .format(self.ad_domain))
            res = self.ad.run_command(['powershell', '-c', cmd])
            assert subordinate_suffix in res.stdout_text

            # Verify IPA does not receive subordinate suffix from AD
            self.master.run_command(
                ['ipa', 'trust-fetch-domains', self.ad_domain],
                ok_returncode=1)
            res = self.master.run_command(
                ['ipa', 'trust-show', self.ad_domain])
            assert subordinate_suffix not in res.stdout_text

            # Set UPN for the AD user
            upn = 'testuser@' + subordinate_suffix
            cmd = 'Set-Aduser -UserPrincipalName {} -Identity testuser'.format(
                upn)
            self.ad.run_command(['powershell', '-c', cmd])

            # Check user resolution
            res = self.master.run_command(['getent', 'passwd', upn])
            expected_regex = (
                r'^testuser@{domain}:\*:(\d+):(\d+):'
                r'Test User:/home/{domain}/testuser:{shell}$'
                    .format(domain=re.escape(self.ad_domain),
                            shell=self.default_shell))
            assert re.search(expected_regex, res.stdout_text)

            # Check user authentication
            self.master.run_command(
                ['kinit', '-E', upn], stdin_text='Secret123')
        finally:
            # cleanup
            tasks.kdestroy_all(self.master)
            cmd = ('Set-ADForest -Identity {} -UPNSuffixes @{{Remove="{}"}}'
                   .format(self.ad_domain, subordinate_suffix))
            self.ad.run_command(['powershell', '-c', cmd])

    def test_remove_nonposix_trust(self):
        self.remove_trust(self.ad)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

