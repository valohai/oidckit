from typing import Optional, Union
from urllib.parse import urlencode

from oidckit.crypto import get_random_string
from oidckit.excs import OIDCError
from oidckit.objects import (
    AuthenticationRequest,
    AuthenticationResult,
    AuthenticationState,
)
from oidckit.provider import OIDCProvider


def build_authentication_request(
    provider: OIDCProvider,
    *,
    request: Optional[object] = None,
    redirect_uri: str,
    state: Optional[str] = None,
    state_size: Optional[int] = 32,
    nonce_size: Optional[int] = 32,
) -> AuthenticationRequest:
    if not state:
        state = get_random_string(state_size)

    params = provider.build_authentication_request_params(
        request=request,
        redirect_uri=redirect_uri,
        state=state,
    )
    if nonce_size > 0:
        nonce = get_random_string(nonce_size)
        params.update({"nonce": nonce})
    else:
        nonce = None

    return AuthenticationRequest(
        redirect_url=f"{provider.config.op_authorization_endpoint}?{(urlencode(params))}",
        auth_state=AuthenticationState(
            nonce=nonce,
            state=state,
            redirect_uri=redirect_uri,
        ),
    )


def process_callback_data(
    *,
    provider: OIDCProvider,
    code: Optional[str],
    state: Optional[str],
    auth_state: Union[AuthenticationState, dict],
    verify: bool = True,
) -> AuthenticationResult:
    if not (code and state):
        raise OIDCError("Missing code and state parameters.")

    if isinstance(auth_state, dict):
        auth_state = AuthenticationState(**auth_state)

    if state != auth_state.state:
        raise OIDCError("Unexpected state code.")

    token_payload = provider.build_token_request_payload(
        code=code,
        auth_state=auth_state,
    )
    token = provider.retrieve_token(token_payload)
    auth_result = AuthenticationResult(
        provider=provider,
        auth_state=auth_state,
        token=token,
    )
    if verify:
        auth_result.decode_id_token()
    return auth_result
