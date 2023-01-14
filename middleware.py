from warnings import warn

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse, HttpRequest
from django.http.response import HttpResponseBase

from .lib import (jsonDumps, jsonLoads, RsaBase64Cipher, AesBase64Cipher, JsonRequestType, )
from .exception import HttpError

rsaCipher = None
try:
    rsaCipher = RsaBase64Cipher(privateKey=settings.RSA_PRIVATE_KEY)
except:
    warn('Invalid rsa private key, RequestDecryptMiddleware may crash.')


class RequestDecryptMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request: HttpRequest) -> None | dict:
        encryptType = request.META.get('HTTP_ENCRYPT')
        if not encryptType:
            return None
        if encryptType == 'RSA':
            try:
                request.bodyDecrypt = rsaCipher.decrypt(request.body)
                return None
            except Exception as error:
                return {
                    'result': -1,
                    'status': HttpError.BadRequest,
                    'message': 'RSA解密失败',
                    'error': error,
                }

        if encryptType == 'AES':
            try:
                aesCipher = AesBase64Cipher(request.session.get('aesKey'))
                request.bodyDecrypt = aesCipher.decrypt(request.body)
            except Exception as error:
                return {
                    'result': -1,
                    'status': HttpError.BadRequest,
                    'message': 'AES解密失败',
                    'error': error,
                }

        raise HttpError(HttpError.BadRequest, '不支持的加密方式', )


class JsonRequestMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request: JsonRequestType) -> None | dict:
        """
        如果 content-type 是 application/json, 尝试解析 request.body 保存至 request.JsonData .
        解析失败就直接返回 BadRequest.
        """
        request.JsonData = None
        if request.method == 'POST' and request.META.get('CONTENT_TYPE') == 'application/json':
            if not request.body:
                return None
            try:
                if hasattr(request, 'bodyDecrypt'):
                    jsonData = request.bodyDecrypt
                else:
                    jsonData = request.body

                request.JsonData = jsonLoads(jsonData)
                assert isinstance(request.JsonData, dict, ), 'JSON数据不是Dict'

            except Exception as error:
                return {
                    'error': error,
                    'result': -1,
                    'status': HttpError.BadRequest,
                    'message': '无效的JSON请求',
                }


class JsonResponseMiddleware(MiddlewareMixin):
    @staticmethod
    def process_response(request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        自动将非 HttpResponse 类型的返回值转换为 HttpResponse.
        """
        if isinstance(response, HttpResponseBase):
            return response  # 如果类型是 HttpResponse 直接返回

        responseData = {
            'result': 0,
            'message': '已完成',
            'data': None,
        }
        status = 200

        if isinstance(response, dict):  # dict 导出 status/result/message
            status = response.get('status', 200)
            if 'result' in response:
                responseData['result'] = response.pop('result')
            if 'message' in response:
                responseData['message'] = response.pop('message')

        if isinstance(response, str):  # str 放入 message
            responseData['message'] = response

        responseData['data'] = response  # 剩余数据放入 data

        return HttpResponse(
            status=status,
            content=jsonDumps(responseData),
            content_type='application/json',
        )


class ExceptionProcessMiddleware(MiddlewareMixin):
    @staticmethod
    def process_exception(request: HttpRequest, exception: Exception):
        """
        将 exception
        """
        if isinstance(exception, HttpError):
            responseData = {
                'result': -1,
                'status': exception.status,
                'message': exception.message,
                **exception.data,
            }
            if exception.error is not None:
                responseData['error'] = exception.error
            return responseData

        status = HttpError.ServerError
        if isinstance(exception, AssertionError):
            status = HttpError.BadRequest

        return {
            'result': -1,
            'status': status,
            'message': str(exception),
            'error': exception.__class__.__name__,
        }
