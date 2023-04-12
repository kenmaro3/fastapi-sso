"""SSO login base dependency
"""
# pylint: disable=too-few-public-methods

import json
import sys
import warnings
from typing import Any, Dict, List, Optional

import httpx
import pydantic
from oauthlib.oauth2 import WebApplicationClient
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

DiscoveryDocument = TypedDict(
    "DiscoveryDocument", {"authorization_endpoint": str, "token_endpoint": str, "userinfo_endpoint": str, "signup_endpoint": str, "signup_info_endpoint": str, "agreement_endpoint": str}
)


class UnsetStateWarning(UserWarning):
    """Warning about unset state parameter"""


class SSOLoginError(HTTPException):
    """Raised when any login-related error ocurrs
    (such as when user is not verified or if there was an attempt for fake login)
    """


class SignUpInfo(pydantic.BaseModel):  # pylint: disable=no-member
    """Class (schema) to represent information got from sso provider in a common form."""

    provider: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    birthday: Optional[str] = None
    age: Optional[str] = None
    picture: Optional[str] = None
    sex: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None

class AgreementInfo(pydantic.BaseModel):  # pylint: disable=no-member
    """Class (schema) to represent information got from sso provider in a common form."""

    provider: Optional[str] = None
    agreement_id: Optional[str] = None
    user_id: Optional[str] = None
    agreement: Optional[bool] = None

class OpenID(pydantic.BaseModel):  # pylint: disable=no-member
    """Class (schema) to represent information got from sso provider in a common form."""

    provider: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    birthday: Optional[str] = None
    age: Optional[str] = None
    picture: Optional[str] = None
    sex: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None


# pylint: disable=too-many-instance-attributes
class SSOBase:
    """Base class (mixin) for all SSO providers"""

    provider: str = NotImplemented
    client_id: str = NotImplemented
    client_secret: str = NotImplemented
    redirect_uri: Optional[str] = NotImplemented
    redirect_uri_signup: Optional[str] = NotImplemented
    redirect_uri_agreement: Optional[str] = NotImplemented
    scope: List[str] = NotImplemented
    _oauth_client: Optional[WebApplicationClient] = None
    additional_headers: Optional[Dict[str, Any]] = None

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: Optional[str] = None,
        redirect_uri_signup: Optional[str] = None,
        redirect_uri_agreement: Optional[str] = None,
        allow_insecure_http: bool = False,
        use_state: bool = False,
        scope: Optional[List[str]] = None,
    ):
        # pylint: disable=too-many-arguments
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.redirect_uri_signup = redirect_uri_signup
        self.redirect_uri_agreement = redirect_uri_agreement
        self.allow_insecure_http = allow_insecure_http
        # TODO: Remove use_state argument and attribute
        if use_state:
            warnings.warn(
                (
                    "Argument 'use_state' of SSOBase's constructor is deprecated and will be removed in "
                    "future releases. Use 'state' argument of individual methods instead."
                ),
                DeprecationWarning,
            )
        self.scope = scope or self.scope
        self._refresh_token: Optional[str] = None
        self._state: Optional[str] = None

    @property
    def state(self) -> Optional[str]:
        """Gets state as it was returned from the server"""
        if self._state is None:
            warnings.warn(
                "'state' parameter is unset. This means the server either "
                "didn't return state (was this expected?) or 'verify_and_process' hasn't been called yet.",
                UnsetStateWarning,
            )
        return self._state

    @property
    def oauth_client(self) -> WebApplicationClient:
        """OAuth Client to help us generate requests and parse responses"""
        if self.client_id == NotImplemented:
            raise NotImplementedError(f"Provider {self.provider} not supported")
        if self._oauth_client is None:
            self._oauth_client = WebApplicationClient(self.client_id)
        return self._oauth_client

    @property
    def access_token(self) -> Optional[str]:
        """Access token from token endpoint"""
        return self.oauth_client.access_token

    @property
    def refresh_token(self) -> Optional[str]:
        """Get refresh token (if returned from provider)"""
        return self._refresh_token or self.oauth_client.refresh_token

    @classmethod
    async def openid_from_response(cls, response: dict) -> OpenID:
        """Return {OpenID} object from provider's user info endpoint response"""
        raise NotImplementedError(f"Provider {cls.provider} not supported")

    async def get_discovery_document(self) -> DiscoveryDocument:
        """Get discovery document containing handy urls"""
        raise NotImplementedError(f"Provider {self.provider} not supported")

    @property
    async def authorization_endpoint(self) -> Optional[str]:
        """Return `authorization_endpoint` from discovery document"""
        discovery = await self.get_discovery_document()
        return discovery.get("authorization_endpoint")

    @property
    async def signup_endpoint(self) -> Optional[str]:
        """Return `signup_endpoint` from discovery document"""
        discovery = await self.get_discovery_document()
        return discovery.get("signup_endpoint")

    @property
    async def agreement_endpoint(self) -> Optional[str]:
        """Return `agreement_endpoint` from discovery document"""
        discovery = await self.get_discovery_document()
        return discovery.get("agreement_endpoint")

    @property
    async def token_endpoint(self) -> Optional[str]:
        """Return `token_endpoint` from discovery document"""
        discovery = await self.get_discovery_document()
        return discovery.get("token_endpoint")

    @property
    async def userinfo_endpoint(self) -> Optional[str]:
        """Return `userinfo_endpoint` from discovery document"""
        discovery = await self.get_discovery_document()
        return discovery.get("userinfo_endpoint")

    @property
    async def signup_info_endpoint(self) -> Optional[str]:
        """Return `signup_info_endpoint` from discovery document"""
        discovery = await self.get_discovery_document()
        return discovery.get("signup_info_endpoint")

    async def get_login_url(
        self,
        *,
        redirect_uri: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> str:
        """Return prepared login url. This is low-level, see {get_login_redirect} instead."""
        params = params or {}
        redirect_uri = redirect_uri or self.redirect_uri
        if redirect_uri is None:
            raise ValueError("redirect_uri must be provided, either at construction or request time")
        request_uri = self.oauth_client.prepare_request_uri(
            await self.authorization_endpoint, redirect_uri=redirect_uri, state=state, scope=self.scope, **params
        )
        return request_uri

    async def get_login_redirect(
        self,
        *,
        redirect_uri: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> RedirectResponse:
        """Return redirect response by Stalette to login page of Oauth SSO provider

        Arguments:
            redirect_uri {Optional[str]} -- Override redirect_uri specified on this instance (default: None)
            params {Optional[Dict[str, Any]]} -- Add additional query parameters to the login request.
            state {Optional[str]} -- Add state parameter. This is useful if you want
                                    the server to return something specific back to you.

        Returns:
            RedirectResponse -- Starlette response (may directly be returned from FastAPI)
        """
        login_uri = await self.get_login_url(redirect_uri=redirect_uri, params=params, state=state)
        response = RedirectResponse(login_uri, 303)
        return response

    async def get_signup_url(
        self,
        *,
        redirect_uri: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> str:
        """Return prepared login url. This is low-level, see {get_login_redirect} instead."""
        params = params or {}
        redirect_uri = redirect_uri or self.redirect_uri
        if redirect_uri is None:
            raise ValueError("redirect_uri must be provided, either at construction or request time")
        request_uri = self.oauth_client.prepare_request_uri(
            await self.signup_endpoint, redirect_uri=redirect_uri, state=state, scope=self.scope, **params
        )
        return request_uri

    async def get_signup_redirect(
        self,
        *,
        redirect_uri: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> RedirectResponse:
        """Return redirect response by Stalette to login page of Oauth SSO provider

        Arguments:
            redirect_uri {Optional[str]} -- Override redirect_uri specified on this instance (default: None)
            params {Optional[Dict[str, Any]]} -- Add additional query parameters to the login request.
            state {Optional[str]} -- Add state parameter. This is useful if you want
                                    the server to return something specific back to you.

        Returns:
            RedirectResponse -- Starlette response (may directly be returned from FastAPI)
        """
        login_uri = await self.get_signup_url(redirect_uri=redirect_uri, params=params, state=state)
        response = RedirectResponse(login_uri, 303)
        return response

    async def verify_and_process_signup(
        self,
        request: Request,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        redirect_uri_signup: Optional[str] = None,
    ) -> Optional[OpenID]:
        """Get FastAPI (Starlette) Request object and process login.
        This handler should be used for your /callback path.

        Arguments:
            request {Request} -- FastAPI request object (or Starlette)
            params {Optional[Dict[str, Any]]} -- Optional additional query parameters to pass to the provider

        Returns:
            Optional[OpenID] -- OpenID if the login was successfull
        """
        headers = headers or {}
        code = request.query_params.get("code")
        if code is None:
            raise SSOLoginError(400, "'code' parameter was not found in callback request")
        self._state = request.query_params.get("state")
        return await self.process_signup(
            code, request, params=params, additional_headers=headers, redirect_uri_signup=redirect_uri_signup
        )

    async def verify_and_process_agreement(
        self,
        request: Request,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        redirect_uri_agreement: Optional[str] = None,
    ) -> Optional[OpenID]:
        """Get FastAPI (Starlette) Request object and process login.
        This handler should be used for your /callback path.

        Arguments:
            request {Request} -- FastAPI request object (or Starlette)
            params {Optional[Dict[str, Any]]} -- Optional additional query parameters to pass to the provider

        Returns:
            Optional[OpenID] -- OpenID if the login was successfull
        """
        headers = headers or {}
        code = request.query_params.get("code")
        if code is None:
            raise SSOLoginError(400, "'code' parameter was not found in callback request")
        self._state = request.query_params.get("state")
        return await self.process_agreement(
            code, request, params=params, additional_headers=headers, redirect_uri_agreement=redirect_uri_agreement
        )

    async def process_agreement(
        self,
        code: str,
        request: Request,
        *,
        params: Optional[Dict[str, Any]] = None,
        additional_headers: Optional[Dict[str, Any]] = None,
        redirect_uri_agreement: Optional[str] = None,
    ) -> Optional[OpenID]:
        """This method should be called from callback endpoint to verify the user and request user info endpoint.
        This is low level, you should use {verify_and_process} instead.

        Arguments:
            params {Optional[Dict[str, Any]]} -- Optional additional query parameters to pass to the provider
            additional_headers {Optional[Dict[str, Any]]} -- Optional additional headers to be added to all requests
        """
        # pylint: disable=too-many-locals
        params = params or {}
        additional_headers = additional_headers or {}
        additional_headers.update(self.additional_headers or {})
        url = request.url
        scheme = url.scheme
        if not self.allow_insecure_http and scheme != "https":
            current_url = str(url).replace("http://", "https://")
            scheme = "https"
        else:
            current_url = str(url)
        current_path = f"{scheme}://{url.netloc}{url.path}"

        token_url, headers, body = self.oauth_client.prepare_token_request(
            await self.token_endpoint,
            authorization_response=current_url,
            redirect_url=redirect_uri_agreement or self.redirect_uri_agreement or current_path,
            code=code,
            **params,
        )  # type: ignore

        if token_url is None:
            return None

        headers.update(additional_headers)

        auth = httpx.BasicAuth(self.client_id, self.client_secret)
        async with httpx.AsyncClient() as session:
            response = await session.post(token_url, headers=headers, content=body, auth=auth)
            content = response.json()
            self._refresh_token = content.get("refresh_token")
            self.oauth_client.parse_request_body_response(json.dumps(content))

            uri, headers, _ = self.oauth_client.add_token(await self.userinfo_endpoint)
            response = await session.get(uri, headers=headers)
            content = response.json()

        return await self.openid_from_response(content)


    async def get_agreement_url(
        self,
        *,
        agreement_redirect_uri: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> str:
        """Return prepared login url. This is low-level, see {get_login_redirect} instead."""
        params = params or {}
        agreement_redirect_uri = agreement_redirect_uri or self.redirect_uri_agreement
        if agreement_redirect_uri is None:
            raise ValueError("redirect_uri must be provided, either at construction or request time")
        required_scope = "agreement"
        if required_scope not in self.scope:
            raise ValueError("agreement not set in scope")
        request_uri = self.oauth_client.prepare_request_uri(
            await self.agreement_endpoint, redirect_uri=agreement_redirect_uri, state=state, scope=required_scope, **params
        )
        return request_uri

    async def get_agreement_redirect(
        self,
        content: str,
        *,
        agreement_redirect_uri: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> RedirectResponse:
        """Return redirect response by Stalette to login page of Oauth SSO provider

        Arguments:
            redirect_uri {Optional[str]} -- Override redirect_uri specified on this instance (default: None)
            params {Optional[Dict[str, Any]]} -- Add additional query parameters to the login request.
            state {Optional[str]} -- Add state parameter. This is useful if you want
                                    the server to return something specific back to you.

        Returns:
            RedirectResponse -- Starlette response (may directly be returned from FastAPI)
        """
        if params is None:
            params = {}
        params.update({"content": content})
        uri = await self.get_agreement_url(agreement_redirect_uri=agreement_redirect_uri, params=params, state=state)
        response = RedirectResponse(uri, 303)
        return response


    async def process_signup(
        self,
        code: str,
        request: Request,
        *,
        params: Optional[Dict[str, Any]] = None,
        additional_headers: Optional[Dict[str, Any]] = None,
        redirect_uri_signup: Optional[str] = None,
    ) -> Optional[OpenID]:
        """This method should be called from callback endpoint to verify the user and request user info endpoint.
        This is low level, you should use {verify_and_process} instead.

        Arguments:
            params {Optional[Dict[str, Any]]} -- Optional additional query parameters to pass to the provider
            additional_headers {Optional[Dict[str, Any]]} -- Optional additional headers to be added to all requests
        """
        # pylint: disable=too-many-locals
        params = params or {}
        additional_headers = additional_headers or {}
        additional_headers.update(self.additional_headers or {})
        url = request.url
        scheme = url.scheme
        if not self.allow_insecure_http and scheme != "https":
            current_url = str(url).replace("http://", "https://")
            scheme = "https"
        else:
            current_url = str(url)
        current_path = f"{scheme}://{url.netloc}{url.path}"

        token_url, headers, body = self.oauth_client.prepare_token_request(
            await self.token_endpoint,
            authorization_response=current_url,
            redirect_url=redirect_uri_signup or self.redirect_uri_signup or current_path,
            code=code,
            **params,
        )  # type: ignore

        if token_url is None:
            return None

        headers.update(additional_headers)

        auth = httpx.BasicAuth(self.client_id, self.client_secret)
        async with httpx.AsyncClient() as session:
            response = await session.post(token_url, headers=headers, content=body, auth=auth)
            content = response.json()
            self._refresh_token = content.get("refresh_token")
            self.oauth_client.parse_request_body_response(json.dumps(content))

            uri, headers, _ = self.oauth_client.add_token(await self.signup_info_endpoint)
            response = await session.get(uri, headers=headers)
            content = response.json()

        return await self.openid_from_response(content)

    async def verify_and_process(
        self,
        request: Request,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        redirect_uri: Optional[str] = None,
    ) -> Optional[OpenID]:
        """Get FastAPI (Starlette) Request object and process login.
        This handler should be used for your /callback path.

        Arguments:
            request {Request} -- FastAPI request object (or Starlette)
            params {Optional[Dict[str, Any]]} -- Optional additional query parameters to pass to the provider

        Returns:
            Optional[OpenID] -- OpenID if the login was successfull
        """
        headers = headers or {}
        code = request.query_params.get("code")
        if code is None:
            raise SSOLoginError(400, "'code' parameter was not found in callback request")
        self._state = request.query_params.get("state")
        return await self.process_login(
            code, request, params=params, additional_headers=headers, redirect_uri=redirect_uri
        )

    async def process_login(
        self,
        code: str,
        request: Request,
        *,
        params: Optional[Dict[str, Any]] = None,
        additional_headers: Optional[Dict[str, Any]] = None,
        redirect_uri: Optional[str] = None,
    ) -> Optional[OpenID]:
        """This method should be called from callback endpoint to verify the user and request user info endpoint.
        This is low level, you should use {verify_and_process} instead.

        Arguments:
            params {Optional[Dict[str, Any]]} -- Optional additional query parameters to pass to the provider
            additional_headers {Optional[Dict[str, Any]]} -- Optional additional headers to be added to all requests
        """
        # pylint: disable=too-many-locals
        params = params or {}
        additional_headers = additional_headers or {}
        additional_headers.update(self.additional_headers or {})
        url = request.url
        scheme = url.scheme
        if not self.allow_insecure_http and scheme != "https":
            current_url = str(url).replace("http://", "https://")
            scheme = "https"
        else:
            current_url = str(url)
        current_path = f"{scheme}://{url.netloc}{url.path}"

        token_url, headers, body = self.oauth_client.prepare_token_request(
            await self.token_endpoint,
            authorization_response=current_url,
            redirect_url=redirect_uri or self.redirect_uri or current_path,
            code=code,
            **params,
        )  # type: ignore

        if token_url is None:
            return None

        headers.update(additional_headers)

        auth = httpx.BasicAuth(self.client_id, self.client_secret)
        async with httpx.AsyncClient() as session:
            response = await session.post(token_url, headers=headers, content=body, auth=auth)
            content = response.json()
            self._refresh_token = content.get("refresh_token")
            self.oauth_client.parse_request_body_response(json.dumps(content))

            uri, headers, _ = self.oauth_client.add_token(await self.userinfo_endpoint)
            response = await session.get(uri, headers=headers)
            content = response.json()

        return await self.openid_from_response(content)
