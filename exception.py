class HttpError(Exception):
    # http error status for use
    BadRequest = 400
    Unauthorized = 401
    Forbidden = 403
    NotFound = 404
    NotAcceptable = 406
    Conflict = 409

    ServerError = 500
    BadGateway = 502
    ServiceUnavailable = 503

    def __init__(self, status: int, message: str, error: BaseException = None, *_, **kwargs):
        self.status = status
        self.message = message
        self.data = kwargs  # Any kwargs will be appended to the output.
        self.error = str(error)
