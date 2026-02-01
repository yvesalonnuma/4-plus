"""
 HTTP Server Shell
 Author: Yves Alon Nums
 DATE: 1.1.26
 DESCRIPTION: http server that handle GET and POST requests and responding to the client with the appropriate response (200,302,400,403,404,500)
"""
import socket
import logging
import os

QUEUE_SIZE = 10
IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 2
READ_LEN = 1
PROTOCOL_VERSION = 'HTTP/1.1'
DEFAULT_URL = "/index.html"
WEBROOT = 'webroot'
GET_VERB = 'GET'
POST_VERB = 'POST'
OK_STATUS_CODE = 200
OK_TEXT = "OK"
MOVED_TEMPORARILY_STATUS_CODE = 302
MOVED_TEMPORARILY_TEXT = "MOVED TEMPORARILY"
BAD_REQUEST_STATUS_CODE = 400
BAD_REQUEST_TEXT = "BAD REQUEST"
FORBIDDEN_STATUS_CODE = 403
FORBIDDEN_STATUS_TEXT = "FORBIDDEN"
NOT_FOUND_STATUS_CODE = 404
NOT_FOUND_TEXT = "NOT FOUND"
INTERNAL_SERVER_ERROR_STATUS_CODE = 500
INTERNAL_SERVER_ERROR_TEXT = "INTERNAL SERVER ERROR"
READ_BINARY = 'rb'
READ = 'r'
WRITE_BINARY = 'wb'
END_OF_LINE = "\r\n"
END_OF_REQUEST = "\r\n\r\n"
PATH = 'upload'
EQUAL = '='
AND = '&'
DOTE = '.'
QUESTION_MARK = '?'
SLASH = '/'
SPACE = ' '

REDIRECTION_DICTIONARY = {
    '/moved': '/'
}

SHOULD_BE_ENCODES = ['html', 'txt', 'css', 'js']


def calculate_next(variable):
    """
    Calculates the next number according to the given query parameter.
    :param variable: string in the format "num=<number>"
    :return: encoded next number or HTTP error response
    """
    logger.debug(f"[CALC] calculate_next called with: {variable}")

    num_info = variable.split(EQUAL)
    if len(num_info) != 2 or num_info[0] != 'num':
        logger.warning("[CALC] Invalid num format")
        headers = {'Content-Length': '0'}
        response = build_response(BAD_REQUEST_STATUS_CODE, BAD_REQUEST_TEXT, headers)
        return response
    else:
        next_num = 'num=' + str(float(num_info[1]) + 1)
        logger.info(f"[CALC] Next num calculated: {next_num}")
        response = str(next_num).encode()
        print("response: ", response.decode())
        return response


def calculate_area(variables):
    """
    Calculates the area of a triangle using height and width.
    :param variables: query string containing height and width
    :return: encoded area or HTTP error response
    """
    logger.debug(f"[CALC] calculate_area called with: {variables}")
    if len(variables.split(AND)) == 2:
        num1_info = variables.split(AND)[0]
        num2_info = variables.split(AND)[1]
        if len(num1_info.split(EQUAL)) == 2 or len(num2_info.split(EQUAL)) == 2:
            num1_split = num1_info.split(EQUAL)
            num2_split = num2_info.split(EQUAL)
            if (num1_split[0] == 'height' and num2_split[0] == 'width') or \
               (num1_split[0] == 'width' and num2_split[0] == 'height'):
                num1_value = float(num1_split[1])
                num2_value = float(num2_split[1])
                area = (num1_value * num2_value) / 2
                logger.info(f"[CALC] Area calculated: {area}")
                response = str(area).encode()
                print("response: ", response.decode())
                return response

    logger.warning("[CALC] Invalid area parameters")
    headers = {'Content-Length': '0'}
    response = build_response(BAD_REQUEST_STATUS_CODE, BAD_REQUEST_TEXT, headers)
    return response


def upload(image_info, length_to_recv, client_socket):
    """
    Receives binary data from the client and saves it as an image file.
    :param image_info: query string containing the image name
    :param length_to_recv: number of bytes to receive
    :param client_socket: socket object of the client
    :return: encoded HTTP response
    """
    logger.info(f"[UPLOAD] Upload request: {image_info}, length={length_to_recv}")

    try:
        image_name = image_info.split(EQUAL)[1]
        image_path = os.path.join(PATH, image_name)

        counter_bytes_recv = 0
        with open(image_path, WRITE_BINARY) as f:
            while counter_bytes_recv < length_to_recv:
                image_byte = client_socket.recv(READ_LEN)
                f.write(image_byte)
                counter_bytes_recv += 1

        logger.info(f"[UPLOAD] Upload completed: {image_path}")
        response = (str(OK_STATUS_CODE) + " " + OK_TEXT).encode()
        print("response: ", response.decode())
        return response

    except Exception as e:
        print("error: " + str(e))
        logger.error(f"[UPLOAD] Upload failed: {e}")
        headers = {'Content-Length': '0'}
        return build_response(BAD_REQUEST_STATUS_CODE, BAD_REQUEST_TEXT, headers)


def image(image_info):
    """
    Sends an image file from the upload directory to the client.
    :param image_info: query string containing image name
    :return: image bytes or HTTP error response
    """
    logger.debug(f"[IMAGE] Image request: {image_info}")
    try:
        image_name = image_info.split(EQUAL)[1]
        is_file, file_path = find_file_recursive(image_name, PATH)
        if is_file:
            with open(file_path, READ_BINARY) as f:
                screenshot_data = f.read()
            logging.info(f"Screenshot ready: {len(screenshot_data)} bytes")
            return screenshot_data
        else:
            logger.warning("[IMAGE] Image not found")
            response = (str(NOT_FOUND_STATUS_CODE) + SPACE + NOT_FOUND_TEXT).encode()
            return response
    except Exception as e:
        logging.error(f"Send screenshot failed: {e}")
        headers = {'Content-Length': '0'}
        return build_response(BAD_REQUEST_STATUS_CODE, BAD_REQUEST_TEXT, headers)


def find_file_recursive(filename, search_path):
    """
    Searches for a file recursively in a directory.
    :param filename: name of the file
    :param search_path: directory to search in
    :return: tuple (found, full_path)
    """
    logger.debug(f"[FS] Searching for file: {filename}")
    full_path = ''
    found = False
    try:
        for root, dirs, files in os.walk(search_path):
            if filename in files:
                found = True
                full_path = os.path.join(root, filename)
                logger.info(f"[FS] File found: {full_path}")
    except FileNotFoundError:
        logger.error("[FS] Search path not found")

    return found, full_path


def get_file_data(file_name):
    """
    Reads file data from disk.
    :param file_name: path to file
    :return: file content as bytes or None
    """
    logger.debug(f"[FILE] Trying to read file: {file_name}")
    try:
        file_type = file_name.split(DOTE)[-1]
        if file_type in SHOULD_BE_ENCODES:
            with open(file_name, READ) as f:
                file_data = f.read().encode()
        else:
            with open(file_name, READ_BINARY) as f:
                file_data = f.read()

        logger.info(f"[FILE] File loaded successfully ({len(file_data)} bytes)")
        return file_data

    except FileNotFoundError:
        logger.warning(f"[FILE] File not found: {file_name}")
        return None
    except Exception as e:
        logger.error(f"[FILE] Error reading file: {e}")
        return None


def build_response(code_status, status_text, headers, body=b''):
    """
    Builds a full HTTP response.
    :param code_status: HTTP status code
    :param status_text: HTTP status description
    :param headers: dictionary of headers
    :param body: response body in bytes
    :return: HTTP response in bytes
    """
    logger.info(f"[RESPONSE] Building {code_status} {status_text}")

    response_line = PROTOCOL_VERSION + SPACE + str(code_status) + SPACE + status_text + END_OF_LINE
    header_lines = ""

    for key, value in headers.items():
        header_lines += key + ": " + value + END_OF_LINE
        logger.debug(f"[RESPONSE] Header {key}: {value}")

    header_lines += END_OF_LINE
    print("response_line: ", response_line+header_lines)
    http_response = (response_line + header_lines).encode() + body
    logger.info(f"[RESPONSE] Total size: {len(http_response)} bytes")
    logging.info("Response headers: " + response_line + header_lines)

    return http_response


def handle_client_request(resource, client_socket, verb, length):
    """
    Handles the HTTP request logic for a single client.
    :param resource: requested resource
    :param client_socket: client socket
    :param verb: HTTP method
    :param length: content length
    :return: None
    """
    logger.info(f"[REQUEST] Handling resource: {resource}, verb={verb}, length={length}")

    if resource == SLASH:
        logger.debug("[REQUEST] Root requested, redirecting to default URL")
        resource = DEFAULT_URL

    if resource == '/forbidden':
        logger.warning("[REQUEST] Forbidden resource requested")
        headers = {'Content-Length': '0'}
        response = build_response(FORBIDDEN_STATUS_CODE, FORBIDDEN_STATUS_TEXT, headers)
        client_socket.send(response)
        return

    if resource == '/error':
        logger.error("[REQUEST] Forced internal error endpoint called")
        headers = {'Content-Length': '0'}
        response = build_response(INTERNAL_SERVER_ERROR_STATUS_CODE, INTERNAL_SERVER_ERROR_TEXT, headers)
        client_socket.send(response)
        return

    if resource in REDIRECTION_DICTIONARY:
        new_location = REDIRECTION_DICTIONARY[resource]
        logger.info(f"[REQUEST] Redirecting {resource} → {new_location}")
        headers = {'Location': new_location, 'Content-Length': '0'}
        response = build_response(MOVED_TEMPORARILY_STATUS_CODE, MOVED_TEMPORARILY_TEXT, headers)
        client_socket.send(response)
        return

    uri = resource.lstrip(SLASH)

    if QUESTION_MARK in uri:
        function_name, params = uri.split(QUESTION_MARK, 1)
        logger.debug(f"[REQUEST] Dynamic function call: {function_name} params={params}")

        if function_name == 'calculate-next' and verb == GET_VERB:
            response = calculate_next(params)
        elif function_name == 'calculate-area' and verb == GET_VERB:
            response = calculate_area(params)
        elif function_name == 'upload' and verb == POST_VERB:
            response = upload(params, length, client_socket)
        elif function_name == 'image' and verb == GET_VERB:
            response = image(params)
        else:
            logger.warning("[REQUEST] Unknown function or wrong verb")
            headers = {'Content-Length': '0'}
            response = build_response(BAD_REQUEST_STATUS_CODE, BAD_REQUEST_TEXT, headers)

    else:
        filename = WEBROOT + "\\" + uri
        logger.debug(f"[REQUEST] Static file requested: {filename}")
        data = get_file_data(filename)

        if data is None:
            logger.warning("[REQUEST] Static file not found")
            headers = {'Content-Length': '0'}
            response = build_response(NOT_FOUND_STATUS_CODE, NOT_FOUND_TEXT, headers)
            client_socket.send(response)
            return

        file_type = uri.split(DOTE)[-1]
        headers = {
            'Content-Type': file_type,
            'Content-Length': str(len(data))
        }

        response = build_response(OK_STATUS_CODE, OK_TEXT, headers, data)
        logger.info("[RESPONSE] 200 OK sent")

    client_socket.send(response)


def validate_http_request(client_request):
    """
    Validates an HTTP request line.
    :param client_request: raw HTTP request line
    :return: tuple (is_valid, requested_resource, verb)
    """
    logger.debug(f"[REQUEST] Validating request: {client_request}")
    valid_request = False

    client_request_split = client_request.split(SPACE)

    requested_line = client_request_split[1]

    verb = client_request_split[0]

    if (verb == GET_VERB or verb == POST_VERB) and client_request_split[2] == PROTOCOL_VERSION:
        valid_request = True
        logger.debug("[REQUEST] Request validation successful")
    else:
        logger.warning("[REQUEST] Invalid HTTP request")

    return valid_request, requested_line, verb


def handle_client(client_socket):
    """
    Handles communication with a connected client.
    :param client_socket: socket object of the connected client
    :return: None
    """
    try:
        logger.info("[CLIENT] Client connected")
        while True:
            headers = ""
            try:
                while not headers.endswith(END_OF_REQUEST):
                    headers += client_socket.recv(READ_LEN).decode()
            except Exception as e:
                logger.error(f"[CLIENT] Header receive failed: {e}")
                headers = {'Content-Length': '0'}
                response = build_response(NOT_FOUND_STATUS_CODE, NOT_FOUND_TEXT, headers)
                client_socket.send(response)
                break
            print(headers)
            logger.debug(f"[CLIENT] Headers received:\n{headers}")
            client_request = headers.split(END_OF_LINE)[0]

            length = 0
            for line in headers.split(END_OF_LINE):
                if line.startswith("Content-Length"):
                    length = int(line.split(":")[1])
                    logger.debug(f"[CLIENT] Content-Length parsed: {length}")

            valid_http, resource, verb = validate_http_request(client_request)

            if valid_http:
                logger.info("[REQUEST] Valid HTTP request")
                handle_client_request(resource, client_socket, verb, length)
                break
            else:
                logger.warning("[REQUEST] Invalid HTTP request – sending 404")
                headers = {'Content-Length': '0'}
                response = build_response(NOT_FOUND_STATUS_CODE, NOT_FOUND_TEXT, headers)
                client_socket.send(response)
                break

    except socket.timeout:
        logger.warning("[CLIENT] Request timeout")
    except Exception as e:
        logger.error(f"[CLIENT] Unexpected error: {e}")


def main():
    """
    Starts the HTTP server and listens for incoming connections.
    :return: None
    """
    logger.info("[SERVER] Server starting")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((IP, PORT))
        server_socket.listen(QUEUE_SIZE)
        print(f"Listening for connections on port {PORT}")
        logger.info(f"[SERVER] Listening on {IP}:{PORT}")

        while True:
            client_socket, client_address = server_socket.accept()
            logger.info(f"[SERVER] New connection from {client_address}")

            try:
                client_socket.settimeout(SOCKET_TIMEOUT)
                handle_client(client_socket)
            finally:
                client_socket.close()
                logger.debug("[SERVER] Client socket closed")

    except Exception as e:
        logger.critical(f"[SERVER] Fatal error: {e}")
    finally:
        server_socket.close()
        logger.info("[SERVER] Server shutdown")


if __name__ == "__main__":
    logging.basicConfig(
        filename="server.log",
        format="%(asctime)s | %(levelname)s | %(message)s",
        filemode="w"
    )
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)


    check_validation, check_requested_line,check_verb = validate_http_request('GET / HTTP/1.1')
    assert check_validation is True, "didn't succeed validation"
    assert check_requested_line == '/', "didn't return the right requested line"
    assert check_verb == 'GET', "didn't return the right verb"
    data = get_file_data(WEBROOT + "\\" + DEFAULT_URL)
    assert data is not None, "didn't return the right data"

    check_response = build_response(FORBIDDEN_STATUS_CODE, FORBIDDEN_STATUS_TEXT,{'Content-Length': '0'})
    assert check_response == b'HTTP/1.1 403 FORBIDDEN\r\nContent-Length: 0\r\n\r\n',"didn't return the right response"

    check_next_num = calculate_next('')
    assert calculate_area('height=7&width=7') == '24.5'.encode(), "didn't return the right area"
    assert calculate_next('num=21') == 'num=22.0'.encode(), "didn't return the right number" #din david 22#

    print("all asserts passed")
    logging.info("all asserts passed")
    main()
