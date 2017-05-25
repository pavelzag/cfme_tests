from fauxfactory import gen_alphanumeric, gen_integer
import pytest
from itertools import product
from cfme.containers.provider import ContainersProvider
from cfme.containers.provider.openshift import OpenshiftProvider
from cfme.exceptions import FlashMessageException
from cfme.web_ui import flash
from utils import testgen
from utils.version import current_version

pytestmark = [
    pytest.mark.uncollectif(lambda: current_version() < "5.8.0.3")]
pytest_generate_tests = testgen.generate([ContainersProvider], scope='module')

DEFAULT_SEC_PROTOCOLS = 'SSL trusting custom CA', 'SSL without validation', 'SSL'
HAWKULAR_SEC_PROTOCOLS = 'SSL trusting custom CA', 'SSL without validation', 'SSL'

alphanumeric_name = gen_alphanumeric(10)
long_alphanumeric_name = gen_alphanumeric(100)
integer_name = str(gen_integer(0, 100000000))
PROVIDER_NAMES = alphanumeric_name, long_alphanumeric_name, integer_name


@pytest.mark.parametrize('provider_names', PROVIDER_NAMES)
@pytest.mark.usefixtures('has_no_containers_providers')
@pytest.mark.polarion('CMP-9836')
def test_add_provider_naming_conventions(provider, provider_names, soft_assert):
    """" This test is checking ability to add Providers with different names:

    Steps:
        * Navigate to Containers Menu
        * Navigate to Add Provider Menu
        * Try to add a Container Provider with each of the following generated names:
            - Alphanumeric name
            - Long Alphanumeric name
            - Integer name
        * Assert that provider was added successfully with each of those
    """
    prov = OpenshiftProvider(
        sec_protocol='SSL',
        name=provider_names,
        hostname=str(provider.hostname),
        credentials=provider.credentials
    )
    try:
        prov.create()
        flash.assert_message_contain('Containers Providers "' + provider_names + '" was saved')
    except FlashMessageException:
        soft_assert(False, provider_names + ' wasn\'t added successfully')
    ContainersProvider.clear_providers()


@pytest.mark.parametrize('default_sec_protocols', DEFAULT_SEC_PROTOCOLS)
@pytest.mark.usefixtures('has_no_containers_providers')
@pytest.mark.polarion('CMP-10586')
def test_add_provider_ssl(provider, default_sec_protocols, soft_assert):
    """ This test checks adding container providers with 3 different security protocols:
    SSL trusting custom CA, SSL without validation and SSL
    Steps:
        * Navigate to Containers Menu
        * Navigate to Add Provider Menu
        * Try to add a Container Provider with each of the following security options:
            Default Endpoint = SSL trusting custom CA/SSL without validation/SSL
        * Assert that provider was added successfully
        """
    prov = OpenshiftProvider(
        sec_protocol=default_sec_protocols,
        name=provider.name,
        hostname=str(provider.hostname),
        hawkular_hostname=str(provider.hawkular_hostname),
        hawkular_api_port=str(provider.hawkular_api_port),
        hawkular_sec_protocol=str(provider.hawkular_sec_protocol),
        credentials=provider.credentials
    )
    try:
        prov.create()
        flash.assert_message_contain('Containers Providers "' + provider.name + '" was saved')
    except FlashMessageException:
        soft_assert(False, provider.name + ' wasn\'t added successfully using '
                    + default_sec_protocols + ' security protocol')
    ContainersProvider.clear_providers()


@pytest.mark.parametrize(('default_sec_protocols', 'hawkular_sec_protocols'),
                         product(DEFAULT_SEC_PROTOCOLS, HAWKULAR_SEC_PROTOCOLS))
@pytest.mark.usefixtures('has_no_containers_providers')
@pytest.mark.polarion('CMP-10586')
def test_add_hawkular_provider_ssl(provider, default_sec_protocols,
                                   hawkular_sec_protocols, soft_assert):
    """This test checks adding container providers with 3 different security protocols:
    SSL trusting custom CA, SSL without validation and SSL
    The test checks the Default Endpoint as well as the Hawkular Endpoint
    Steps:
        * Navigate to Containers Menu
        * Navigate to Add Provider Menu
        * Try to add a Container Provider with each of the following security options:
            Default Endpoint = SSL trusting custom CA/SSL without validation/SSL
            Hawkular Endpoint = SSL trusting custom CA/SSL without validation/SSL
        * Assert that provider was added successfully
        """
    prov = OpenshiftProvider(
        hawkular=True,
        sec_protocol=default_sec_protocols,
        hawkular_sec_protocol=hawkular_sec_protocols,
        name=provider.name,
        hostname=str(provider.hostname),
        hawkular_hostname=str(provider.hawkular_hostname),
        credentials=provider.credentials
    )
    try:
        prov.create()
        flash.assert_message_contain('Containers Providers "' + provider.name + '" was saved')
    except FlashMessageException:
        soft_assert(False, provider.name + ' wasn\'t added successfully using ' +
                    default_sec_protocols + ' security protocol and ' +
                    hawkular_sec_protocols + ' hawkular security protocol')
