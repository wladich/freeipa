import time 
import logging

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


logger = logging.getLogger(__name__)


def install_rpm(host, name):
    host.run_command(['cat', '/etc/resolv.conf'])
    host.run_command(['yum', 'install', '-y', name])


class TestDnf(IntegrationTest):
    topology = 'line'
    num_replicas = 1
    num_clients = 1
    rpm1 = 'nc'
    rpm2 = 'mc'
    rpm3 = 'vim'

    @classmethod
    def install(cls, mh):
        cls.replica = cls.replicas[0]
        cls.client = cls.clients[0]
    
    def test_dnf_master_before_install(self):
        install_rpm(self.master, self.rpm1)
        
    def test_dnf_replica_before_install(self):
        install_rpm(self.replica, self.rpm1)
        
    def test_dnf_client_before_install(self):
        install_rpm(self.client, self.rpm1)
        
    def test_install(self):
        tasks.install_topo(self.topology,
                           self.master, self.replicas,
                           self.clients, 1)

    def test_dnf_master_after_install(self):
        install_rpm(self.master, self.rpm2)

    def test_dnf_replica_after_install(self):
        install_rpm(self.replica, self.rpm2)

    def test_dnf_client_after_install(self):
        install_rpm(self.client, self.rpm2)

    def test_wait_10_minutes(self):
        time.sleep(600)
        
    def test_dnf_master_after_10_minutes(self):
        install_rpm(self.master, self.rpm3)

    def test_dnf_replica_after_10_minutes(self):
        install_rpm(self.replica, self.rpm3)

    def test_dnf_client_after_10_minutes(self):
        install_rpm(self.client, self.rpm3)
