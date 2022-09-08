"""LDaCACILogon OAuthAuthenticator for JupyterHub

This is a subclass of the CILogon OAuthAuthenticator

Uses OAuth 2.0 with cilogon.org (override with CILOGON_HOST)

Caveats:

- For allowed user list /admin purposes, username will be the ePPN by default.
  This is typically an email address and may not work as a Unix userid.
  Normalization may be required to turn the JupyterHub username into a Unix username.
- Default username_claim of ePPN does not work for all providers,
  e.g. generic OAuth such as Google.
  Use `c.LDaCACILogonOAuthenticator.username_claim = 'email'` to use
  email instead of ePPN as the JupyterHub username.
"""
import re

from jupyterhub.auth import LocalAuthenticator
from tornado import web
from traitlets import List, Unicode, validate

from .cilogon import CILogonOAuthenticator


class LDaCACILogonOAuthenticator(CILogonOAuthenticator):
    login_service = "LDaCACILogon"

    # Override CILogonOAuthenticator scope validation
    @validate('scope')
    def _validate_scope(self, proposal):
        """Ensure `openid` and `org.cilogon.userinfo` are always requested
        """
        scopes = proposal.value

        if 'openid' not in proposal.value:
            scopes += ['openid']

        if 'org.cilogon.userinfo' not in proposal.value:
            scopes += ['org.cilogon.userinfo']

        return scopes

    @validate('additional_username_claims')
    def _validate_additional_username_claims(self, proposal):
        """Ensure `eduPersonOrcid` is always requested to make ORCID authenticaton work
        """
        additional_username_claims = proposal.value

        if 'openid' not in proposal.value:
            additional_username_claims += ["eduPersonOrcid"]

        return additional_username_claims

    allowed_cilogon_groups = List(
        Unicode(),
        default_value=["CO:members:all"],
        config=True,
        help="""A list of permitted CILogon groups in the "isMemberOf" field.
        """,
    )

    async def authenticate(self, handler, data=None):
        # Call CILogonOAuthenticator.authenticate()
        userdict = await super().authenticate(self, handler, data)

        # Make fake email address from ORCID URL
        # Need to have "eduPersonOrcid" in hub.config.LdaCACILogonOAuthenticator.additional_username_claims
        if orcid_match := re.match(r'http://(orcid.org)/(\d{4}-\d{4}-\d{4}-\d{4})', userdict["name"]):
            userdict["name"] = f'{orcid_match.group(2)}@{orcid_match.group(1)}'

        isMemberOf = userdict["auth_state"]['cilogon_user'].get("isMemberOf", [])
        if not set(self.allowed_cilogon_groups) & set(isMemberOf):
            self.log.error(
                f"User is not a member of a permitted CILogon group {self.allowed_cilogon_groups}",
            )
            raise web.HTTPError(
                403,
                "User is not a member of a permitted CILogon group",
            )

        return userdict


class LocalLDaCACILogonOAuthenticator(LocalAuthenticator, LDaCACILogonOAuthenticator):
    """A version that mixes in local system user creation"""

    pass
