import time

from appium import webdriver
from selenium.webdriver import ActionChains


class ElementNotFound(Exception):
    pass


class TooManyElementsFound(Exception):
    pass


def find_one_element_by_xpath(parent, selector):
    elements = parent.find_elements_by_xpath(selector)
    if elements:
        if len(elements) > 1:
            raise TooManyElementsFound(selector)
        return elements[0]
    raise ElementNotFound(selector)


class WindowObject:
    window_selector = None

    def __init__(self, driver, selector):
        self.driver = driver
        self.root = find_one_element_by_xpath(driver, selector)

    @classmethod
    def from_runtime_id(cls, driver, runtime_id):
        selector = '//*[@RuntimeId="{}"]'.format(runtime_id)
        return cls(driver, selector)

    @classmethod
    def from_parent(cls, parent, **selector_args):
        process_id = parent.get_attribute('ProcessId')
        assert process_id
        selector = cls.window_selector.format(**selector_args) + '[@ProcessId="{}"]'.format(process_id)
        driver = parent.parent
        return cls(driver, selector)

    @classmethod
    def from_top(cls, driver):
        return cls(driver, cls.window_selector)

    def ensure_element(self, selector_or_element):
        if isinstance(selector_or_element, str):
            return find_one_element_by_xpath(self.root, selector_or_element)
        return selector_or_element

    def find_child_element(self, selector):
        return find_one_element_by_xpath(self.root, selector)

    def context_click(self, element):
        element = self.ensure_element(element)
        ac = ActionChains(self.driver)
        ac.context_click(element).perform()


class TrustConsole(WindowObject):
    domain_item_selector = '//Pane/Tree/TreeItem/TreeItem[@Name="{domain}"]'

    def open_domain_properties(self, domain_name):
        self.context_click(self.domain_item_selector.format(domain=domain_name))
        ContextMenu.from_top(self.driver).click_item('Properties')
        return TrustProperties.from_parent(self.root, domain=domain_name)


class TrustProperties(WindowObject):
    window_selector = '//Window[@Name="{domain} Properties"]'
    tab_selector = '//TabItem[@Name="{name}"]'
    outgoing_trust_item_selector = '//List[@AutomationId="281"]/ListItem[@Name="{domain}"]'
    outgoing_trust_properties_button = '//Button[@AutomationId="276"]'
    incoming_trust_item_selector = '//List[@AutomationId="282"]/ListItem[@Name="{domain}"]'
    incoming_trust_properties_button = '//Button[@AutomationId="279"]'

    def switch_to_tab(self, tab_name):
        self.find_child_element(self.tab_selector.format(name='Trusts')).click()

    def open_incoming_trust_properties(self, domain_name):
        self.find_child_element(self.incoming_trust_item_selector.format(domain=domain_name)).click()
        self.find_child_element(self.incoming_trust_properties_button).click()
        return TrustedDomainProperties.from_parent(self.root, domain=domain_name)

    def open_outgoing_trust_properties(self, domain_name):
        self.find_child_element(self.outgoing_trust_item_selector.format(domain=domain_name)).click()
        self.find_child_element(self.outgoing_trust_properties_button).click()
        return TrustedDomainProperties.from_parent(self.root, domain=domain_name)

class TrustedDomainProperties(WindowObject):
    window_selector = '//Window[@Name="{domain} Properties"]'
    validate_button_selector = '//Button[@Name="Validate"]'

    def start_validate(self):
        self.find_child_element(self.verify_button_selector).click()

class ContextMenu(WindowObject):
    window_selector = '//Menu[@Name="Context"]'
    item_selector = '//MenuItem[@Name="{name}"]'

    def click_item(self, name):
        self.find_child_element(self.item_selector.format(name=name)).click()


class WindowsApps:
    trust_console = {
        'app': 'mmc.exe',
        'app_args': r'c:\windows\system32\domain.msc',
        'window_class': TrustConsole
    }


def get_application_window(host, app, window_class, app_args=None):
    desired_caps = {'app': app}
    if app_args is not None:
        desired_caps['appArguments'] = app_args
    webdriver_url = 'http://{ip}:{port}'.format(ip=host.ip, port=4723)
    app_driver = webdriver.Remote(command_executor=webdriver_url,
                              desired_capabilities=desired_caps)
    root_driver = webdriver.Remote(command_executor=webdriver_url,
                                   desired_capabilities={'app': 'Root'})
    runtime_id = find_one_element_by_xpath(app_driver, 'Window').get_attribute('RuntimeId')
    return window_class.from_runtime_id(root_driver, runtime_id)




if __name__ == '__main__':
    class Host:
        pass

    host = Host()
    host.ip = '192.168.121.20'

    trust_console = get_application_window(host, **WindowsApps.trust_console)
    dom_props = trust_console.open_domain_properties('ad.test')
    dom_props.switch_to_tab('Trusts')
    trust_props = dom_props.open_incoming_trust_properties('testrelm.test')
