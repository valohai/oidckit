import requests


class OIDCError(Exception):
    pass


class RemoteError(requests.RequestException, OIDCError):
    """
    Raised when a remote call fails.
    """

    @classmethod
    def raise_from_status(cls, response: requests.Response):
        try:
            response.raise_for_status()
        except requests.HTTPError as he:
            raise cls(
                he.response.text,
                request=he.request,
                response=he.response,
            ) from he
