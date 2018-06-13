# -*- coding: utf-8 -*-
'''
Module for sending messages to Slack


:configuration: This module can be used by either passing an api key and
    version directly or by specifying both in a configuration profile in
    the salt master/minion config. The built-in module that comes with
    SaltStack does not allow for sending true Slack Attachments. Rather, it
    converts them to text

    For example:

    .. code-block:: yaml

        slack:
          api_key: peWcBiMOS9HrZG15peWcBiMOS9HrZG15
'''

# Import Python libs
from __future__ import absolute_import, unicode_literals, print_function
import logging

# Import Salt libs
import salt.utils.json
import salt.utils.slack
from salt.exceptions import SaltInvocationError

# Import 3rd-party libs
# pylint: disable=import-error,no-name-in-module,redefined-builtin
from salt.ext.six.moves.urllib.parse import urlencode as _urlencode
from salt.ext.six.moves.urllib.parse import urljoin as _urljoin
import salt.ext.six.moves.http_client
# pylint: enable=import-error,no-name-in-module

log = logging.getLogger(__name__)

__virtualname__ = 'slack_adv'


def __virtual__():
    '''
    Return virtual name of the module.

    :return: The virtual name of the module.
    '''
    return __virtualname__


def _get_api_key():
    api_key = __salt__['config.get']('slack.api_key') or \
        __salt__['config.get']('slack:api_key')

    if not api_key:
        raise SaltInvocationError('No Slack API key found.')

    return api_key


def _get_hook_id():
    url = __salt__['config.get']('slack.hook') or \
        __salt__['config.get']('slack:hook')
    if not url:
        raise SaltInvocationError('No Slack WebHook url found')

    return url


def call_hook(message,
              attachment=None,
              color='good',
              short=False,
              identifier=None,
              channel=None,
              username=None,
              icon_emoji=None):
    '''
    Send message to Slack incoming webhook.

    :param message:     The topic of message.
    :param attachment:  The message to send to the Slacke WebHook.
    :param color:       The color of border of left side
    :param short:       An optional flag indicating whether the value is short
                        enough to be displayed side-by-side with other values.
    :param identifier:  The identifier of WebHook.
    :param channel:     The channel to use instead of the WebHook default.
    :param username:    Username to use instead of WebHook default.
    :param icon_emoji:  Icon to use instead of WebHook default.
    :return:            Boolean if message was sent successfully.

    CLI Example:

    .. code-block:: bash

        salt '*' slack.call_hook message='Hello, from SaltStack'

    '''
    base_url = 'https://hooks.slack.com/services/'
    if not identifier:
        identifier = _get_hook_id()

    url = _urljoin(base_url, identifier)

    if not message:
        log.error('message is required option')

    
    if attachment:
        if type(attachment) != dict:
            attachment = salt.utils.json.loads(attachment)
        payload = {
            'attachments': [
               attachment
            ]
        }
    else:
        payload = {
            'text': message,
        }

    if channel:
        payload['channel'] = channel

    if username:
        payload['username'] = username

    if icon_emoji:
        payload['icon_emoji'] = icon_emoji

    data = _urlencode(
        {
            'payload': salt.utils.json.dumps(payload)
        }
    )
    result = salt.utils.http.query(url, method='POST', data=data, status=True)

    if result['status'] <= 201:
        return True
    else:
        return {
            'res': False,
            'message': result.get('body', result['status'])
        }
