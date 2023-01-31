from warnings import warn

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse, HttpRequest
from django.http.response import HttpResponseBase

from .lib import (jsonDumps, jsonLoads, RsaBase64Cipher, AesBase64Cipher, JsonRequestType, JsonResponseDict, )
from .exception import HttpError

rsaCipher = None
try:
    rsaCipher = RsaBase64Cipher(privateKey=settings.RSA_PRIVATE_KEY)
except:
    warn('RSA 私钥无效, RequestDecryptMiddleware 可能会出错.')


class RequestDecryptMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request: JsonRequestType) -> None | dict:
        encryptType = request.headers.get('Body-Encrypt')
        if not encryptType:
            return None
        if encryptType == 'RSA':
            try:
                request.bodyDecrypt = rsaCipher.decrypt(request.body)
                request.encryptType = 'RSA'
                return None
            except Exception as error:
                return {
                    'status': HttpError.BadRequest,
                    'message': 'RSA解密失败',
                    'error': error,
                }

        if encryptType == 'AES':
            try:
                request.bodyDecrypt = AesBase64Cipher(
                    request.session.get('aesKey')
                ).decrypt(
                    request.body
                )
                request.encryptType = 'AES'
            except Exception as error:
                return {
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
        if request.method == 'POST' and (request.headers.get('Content-Type') == 'application/json'
                                         or request.headers.get('Content-Type') == 'text/plain'):
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
                    'status': HttpError.BadRequest,
                    'message': '无效的JSON请求',
                }


class JsonResponseMiddleware(MiddlewareMixin):
    @staticmethod
    # def process_response(request: HttpRequest, response: HttpResponse) -> HttpResponse:
    #     """
    #     Auto convert the result like dict/list/set to HttpResponse.
    #     """
    #     if isinstance(response, HttpResponseBase):
    #         # if this get a HttpResponse, do not process
    #         return response
    #
    #     responseData = {
    #         'result': 0,
    #         'message': '已完成',
    #         'data': None,
    #     }
    #     status = 200
    #
    #     if isinstance(response, dict):
    #         status = response.get('status', 200)
    #         if 'result' in response:
    #             responseData['result'] = response.pop('result')
    #         if 'message' in response:
    #             responseData['message'] = response.pop('message')
    #
    #     if isinstance(response, str):
    #         responseData['message'] = response
    #
    #     responseData['data'] = response
    #
    #     return HttpResponse(
    #         status=status,
    #         content=jsonDumps(responseData),
    #         content_type='application/json',
    #     )

    def process_response(request: HttpRequest, response: JsonResponseDict | HttpResponseBase) -> HttpResponseBase:
        """
        自动将非 HttpResponse 类型的返回值转换为 HttpResponse.
        """
        if isinstance(response, HttpResponseBase):
            return response  # 如果类型是 HttpResponse 直接返回

        responseData = {
            'message': '已完成',
            'result': None,
        }
        status = 200

        if isinstance(response, dict):  # dict 导出 status
            status = response.get('status', 200)
            if 'message' in response:
                responseData['message'] = response.pop('message')

        responseData['result'] = response  # 放入 result

        if isinstance(response, str):  # str 同时更新 message
            responseData['message'] = response

        responseHeader = {}
        responseContent = None

        encryptType = getattr(request, 'encryptType', None)
        aesKey = request.session.get('aesKey')
        if encryptType == 'AES' and aesKey:
            try:
                responseContent = AesBase64Cipher(secretKey=aesKey).encrypt(jsonDumps(responseData))
                responseHeader['encrypt'] = 'AES'
            except:
                responseHeader['encrypt'] = 'AES-FAIL'

        if responseContent is None:
            responseContent = jsonDumps(responseData)

        return HttpResponse(
            status=status,
            content=responseContent,
            content_type='application/json',
            headers=responseHeader,
        )


class ExceptionProcessMiddleware(MiddlewareMixin):
    @staticmethod
    def process_exception(request: HttpRequest, exception: Exception):
        """
        将 exception
        """
        if isinstance(exception, HttpError):
            responseData = {
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
            'status': status,
            'message': str(exception),
            'error': exception.__class__.__name__,
        }
