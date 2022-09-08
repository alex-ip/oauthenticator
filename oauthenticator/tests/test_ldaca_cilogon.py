import json
import logging

from jsonschema.exceptions import ValidationError
from pytest import fixture, raises
from tornado.web import HTTPError
from traitlets.config import Config
from traitlets.traitlets import TraitError

from .mocks import setup_oauth_mock
from ..ldaca_cilogon import LDaCACILogonOAuthenticator


def user_model(username):
    """Return a user model"""
    return {
        'eppn': username + '@serenity.space',
        "isMemberOf": [
            "CO:members:all",
            "CO:admins",
            "OIDC mgrs",
            "CO:members:active"
        ],
    }


def alternative_user_model(username, claimname, **kwargs):
    """Return a user model with alternate claim name"""
    return {
        claimname: username,
        "isMemberOf": [
            "CO:members:all",
            "CO:admins",
            "OIDC mgrs",
            "CO:members:active"
        ],
        **kwargs
    }


@fixture
def ldaca_cilogon_client(client):
    setup_oauth_mock(
        client,
        host='cilogon.org',
        access_token_path='/oauth2/token',
        user_path='/oauth2/userinfo',
        token_type='token',
    )
    return client


async def test_cilogon(ldaca_cilogon_client):
    authenticator = LDaCACILogonOAuthenticator()
    handler = ldaca_cilogon_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'wash@serenity.space'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': user_model('wash'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_alternate_claim(ldaca_cilogon_client):
    authenticator = LDaCACILogonOAuthenticator(username_claim='uid')
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid')
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk@ufp.gov'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model('jtkirk@ufp.gov', 'uid'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_additional_claim(ldaca_cilogon_client):
    authenticator = LDaCACILogonOAuthenticator(additional_username_claims=['uid'])
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid')
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk@ufp.gov'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model('jtkirk@ufp.gov', 'uid'),
        'token_response': auth_state['token_response'],
    }


async def test_cilogon_missing_alternate_claim(ldaca_cilogon_client):
    authenticator = LDaCACILogonOAuthenticator()
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model('jtkirk@ufp.gov', 'uid')
    )
    with raises(HTTPError):
        user_info = await authenticator.authenticate(handler)


def test_deprecated_config(caplog):
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.idp_whitelist = ['pink']

    log = logging.getLogger('testlog')
    with raises(
            ValueError,
            match='LDaCACILogonOAuthenticator.idp_whitelist is deprecated in LDaCACILogonOAuthenticator 0.12.0, use '
                  'LDaCACILogonOAuthenticator.allowed_idps instead',
    ):
        LDaCACILogonOAuthenticator(config=cfg, log=log)
    log_msgs = caplog.record_tuples
    print(log_msgs)

    expected_deprecation_error = (
        log.name,
        logging.ERROR,
        'LDaCACILogonOAuthenticator.idp_whitelist is deprecated in LDaCACILogonOAuthenticator 0.12.0, use '
        'LDaCACILogonOAuthenticator.allowed_idps instead',
    )

    assert expected_deprecation_error in log_msgs


def test_allowed_idps_wrong_type(caplog):
    # Test alllowed_idps is a dict
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = ['pink']

    with raises(TraitError):
        LDaCACILogonOAuthenticator(config=cfg)


async def test_allowed_idps_required_username_derivation(caplog):
    # Test username_derivation is a required field of allowed_idps
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {}
    }

    with raises(ValidationError, match="'username_derivation' is a required property"):
        LDaCACILogonOAuthenticator(config=cfg)


def test_allowed_idps_invalid_entity_id(caplog):
    # Test allowed_idps keys cannot be domains, but only valid CILogon entity ids,
    # i.e. only fully formed URLs
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'uni.edu': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
                'domain': 'uni.edu',
            }
        }
    }
    log = logging.getLogger('testlog')

    with raises(ValueError):
        LDaCACILogonOAuthenticator(config=cfg, log=log)

    log_msgs = caplog.record_tuples

    expected_deprecation_error = (
        log.name,
        logging.ERROR,
        "Trying to allow an auth provider: uni.edu, that doesn't look like a valid CILogon EntityID.",
    )

    assert expected_deprecation_error in log_msgs


async def test_allowed_idps_invalid_config_option(caplog):
    cfg = Config()
    # Test config option not recognized
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': 'invalid'
    }

    with raises(ValidationError, match="'invalid' is not of type 'object'"):
        LDaCACILogonOAuthenticator(config=cfg)


async def test_allowed_idps_invalid_config_type(caplog):
    cfg = Config()
    # Test username_derivation not dict
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': 'username_derivation'
    }

    with raises(ValidationError, match="'username_derivation' is not of type 'object'"):
        LDaCACILogonOAuthenticator(config=cfg)


async def test_allowed_idps_invalid_config_username_derivation_options(caplog):
    cfg = Config()
    # Test username_derivation not dict
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {
            'username_derivation': {'a': 1, 'b': 2}
        }
    }

    with raises(ValidationError, match='Additional properties are not allowed') as e:
        LDaCACILogonOAuthenticator(config=cfg)


async def test_allowed_idps_invalid_config_username_domain_stripping(caplog):
    cfg = Config()
    # Test username_derivation not dict
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
            }
        }
    }

    with raises(ValidationError, match="'domain' is a required property"):
        LDaCACILogonOAuthenticator(config=cfg)


async def test_allowed_idps_invalid_config_username_prefix(caplog):
    cfg = Config()
    # Test username_derivation not dict
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://github.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'prefix',
            }
        }
    }

    with raises(ValidationError, match="'prefix' is a required property"):
        LDaCACILogonOAuthenticator(config=cfg)


async def test_cilogon_scopes():
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'prefix',
                'prefix': 'hub',
            }
        }
    }
    cfg.LDaCACILogonOAuthenticator.scope = ['email']

    authenticator = LDaCACILogonOAuthenticator(config=cfg)
    expected_scopes = ['email', 'openid', 'org.cilogon.userinfo']

    assert authenticator.scope == expected_scopes


async def test_strip_and_prefix_username(ldaca_cilogon_client):
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
                'domain': 'uni.edu',
            }
        },
        'https://another-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'nickname',
                'action': 'prefix',
                'prefix': 'idp',
            }
        },
    }

    authenticator = LDaCACILogonOAuthenticator(config=cfg)

    # Test stripping domain
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@uni.edu', 'email', idp='https://some-idp.com/login/oauth/authorize'
        )
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'jtkirk'

    # Test appending prefixes
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk', 'nickname', idp='https://another-idp.com/login/oauth/authorize'
        )
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == 'idp:jtkirk'


async def test_no_action_specified(ldaca_cilogon_client):
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
            }
        },
    }

    authenticator = LDaCACILogonOAuthenticator(config=cfg)

    # Test stripping domain
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@uni.edu', 'email', idp='https://some-idp.com/login/oauth/authorize'
        )
    )
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'jtkirk@uni.edu'


async def test_not_allowed_domains_and_stripping(ldaca_cilogon_client):
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
                'domain': 'uni.edu',
            },
            'allowed_domains': ['pink.org'],
        },
    }

    authenticator = LDaCACILogonOAuthenticator(config=cfg)

    # Test stripping domain not allowed
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@uni.edu', 'email', idp='https://some-idp.com/login/oauth/authorize'
        )
    )

    # The domain to be stripped isn't allowed, so it should fail
    with raises(HTTPError):
        user_info = await authenticator.authenticate(handler)


async def test_allowed_domains_and_stripping(ldaca_cilogon_client):
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
                'action': 'strip_idp_domain',
                'domain': 'pink.org',
            },
            'allowed_domains': ['pink.org'],
        },
    }

    authenticator = LDaCACILogonOAuthenticator(config=cfg)

    # Test stripping allowed domain
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@pink.org', 'email', idp='https://some-idp.com/login/oauth/authorize'
        )
    )

    # The domain to be stripped is allowed, so it should be stripped
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'jtkirk'


async def test_allowed_domains_no_stripping(ldaca_cilogon_client):
    cfg = Config()
    cfg.LDaCACILogonOAuthenticator.allowed_idps = {
        'https://some-idp.com/login/oauth/authorize': {
            'username_derivation': {
                'username_claim': 'email',
            },
            'allowed_domains': ['pink.org'],
        },
    }

    authenticator = LDaCACILogonOAuthenticator(config=cfg)

    # Test domain not allowed
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@uni.edu', 'email', idp='https://some-idp.com/login/oauth/authorize'
        )
    )

    with raises(HTTPError):
        user_info = await authenticator.authenticate(handler)

    # Test allowed domain login
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model(
            'jtkirk@pink.org', 'email', idp='https://some-idp.com/login/oauth/authorize'
        )
    )

    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'jtkirk@pink.org'


async def test_orcid_auth(ldaca_cilogon_client):
    """Tests creation of fake email address from ORCID URL"""
    authenticator = LDaCACILogonOAuthenticator(username_claim='email', additional_username_claims=['eduPersonOrcid'])
    handler = ldaca_cilogon_client.handler_for_user(
        alternative_user_model("http://orcid.org/0000-0001-8937-8904", "eduPersonOrcid")
    )
    user_info = await authenticator.authenticate(handler)
    print(json.dumps(user_info, sort_keys=True, indent=4))
    name = user_info['name']
    assert name == '0000-0001-8937-8904@orcid.org'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'token_response' in auth_state
    assert auth_state == {
        'access_token': auth_state['access_token'],
        'cilogon_user': alternative_user_model("http://orcid.org/0000-0001-8937-8904", "eduPersonOrcid"),
        'token_response': auth_state['token_response'],
    }


async def test_failed_group_auth(ldaca_cilogon_client):
    """Tests for failed group authorisation"""
    authenticator = LDaCACILogonOAuthenticator(allowed_cilogon_groups=['some group'])
    handler = ldaca_cilogon_client.handler_for_user(
        user_model(username='wash')
    )
    with raises(HTTPError):
        user_info = await authenticator.authenticate(handler)
