import json
import requests
import re


class Sensitive_Info_Extractor:
    def __init__(self, subdomains):
        self.subdomains = subdomains
        self.results = []
        self.password_keywords = [
            'password', 'pass', 'passwd', 'pwd', 'user_pass', 'user_password', 'passcode',
            'client_secret', 'secret', 'password_hash', 'userauth', 'api_secret', 'app_secret',
            'app_key', 'client_password', 'client_token', 'db_password', 'encryption_key',
            'private_key', 'secret_key', 'ssh_key', 'auth_key', 'session_key', 'symmetric_key',
            'unlock_code', 'verification_code', 'oauth_token', 'refresh_token', 'account_key',
            'billing_key', 'master_key', 'master_password', 'root_password', 'login_password',
            'admin_password', 'service_password', 'key_password', 'cert_password', 'keystore_password',
            'truststore_password', 'ssl_password', 'proxy_password', 'ldap_password', 'wifi_password',
            'pin', 'p12_password', 'jks_password', 'zip_password', 'unlock_key', 'identity_key',
            'client_key', 'cookie', 'basic_auth', 'api_password', 'auth_password', 'secret_code',
            'backup_password', 'account_password', 'application_password', 'user_key', 'pass_key',
            'verification_key', 'signature_key', 'security_key', 'system_password', 'temp_password',
            'passphrase', 'api_secret_key', 'encryption_password', 'access_code', 'app_password',
            'user_secret', 'db_secret', 'service_key', 'connection_string', 'jdbc_url', 'db_url',
            'db_username', 'db_user', 'db_name', 'api_username', 'app_username', 'client_username',
            'admin_username', 'service_username', 'username_field', 'user_token', 'user_access_token',
            'user_jwt', 'client_token', 'client_jwt', 'api_token', 'service_token', 'auth_token',
            'session_token', 'security_token', 'token_key', 'api_key', 'access_key', 'api_secret_key',
            'auth_key', 'secret_key', 'service_key', 'encryption_key', 'session_key',
            'app_key', 'signing_key', 'access_token', 'id_token', 'jwt', 'oauth', 'api_auth',
            'api_authentication', 'api_authorization', 'authentication_token', 'authorization_token',
            'otp', 'one_time_password', 'code_token', 'sms_token', 'email_token', 'temp_token',
            'verification_token', 'reset_token', 'confirmation_token', 'token_code', 'security_code',
            'pin_code', 'validation_code', 'verification_code', 'activation_code', 'ticket_code',
            'confirmation_code', 'qr_code', 'captcha_code', 'captcha_token', '2fa_token', '2fa_code'
            ]
        self.key_keywords = [
            'api_key', 'app_key', 'access_key', 'secret_key', 'client_key', 'service_key',
            'encryption_key', 'session_key', 'signing_key', 'oauth_key', 'jwt_key', 'token_key',
            'auth_key', 'secret_token', 'client_token', 'service_token', 'verification_key',
            'encryption_secret', 'api_secret', 'access_secret', 'secret_value',
            'service_secret', 'app_secret', 'password_salt', 'hmac_key', 'rsa_key', 'rsa_private_key',
            'rsa_public_key', 'ecdsa_key', 'ecdsa_private_key', 'ecdsa_public_key', 'ssl_key',
            'pem_key', 'jks_key', 'keystore_key', 'truststore_key', 'ssh_private_key', 'ssh_public_key',
            'private_key_path', 'public_key_path', 'certificate', 'ssl_certificate', 'pem_certificate',
            'cert_path', 'certificate_path', 'ssl_cert_path', 'pem_cert_path', 'ssl_certificate_path',
            'truststore', 'keystore', 'ssl_truststore', 'ssl_keystore', 'truststore_path', 'keystore_path',
            'ssl_truststore_path', 'ssl_keystore_path', 'config_file', 'properties_file', 'key_file',
            'ini_file', 'json_file', 'xml_file', 'yml_file', 'file_path', 'file_location', 'file_directory',
            'backup_file', 'config_path', 'properties_path', 'key_path', 'ini_path', 'json_path', 'xml_path',
            'yml_path', 'file_url', 'download_link', 'data_source', 'connection_string', 'database_url',
            'db_url', 'api_url', 'service_url', 'endpoint_url', 'callback_url', 'redirect_url',
            'authorization_url', 'login_url', 'logout_url', 'upload_url', 'download_url', 'image_url',
            'video_url', 'audio_url', 'file_url', 'cdn_url', 'proxy_url', 'third_party_url'
]
        self.username_keywords = [
             'username', 'user', 'client_id', 'customer_id', 'account_id', 'login', 'userid', 'user_id',
             'account', 'client_name', 'customer_name', 'user_name', 'user_id', 'profile_id',
             'admin_username', 'service_username', 'username_field', 'user_key', 'app_username',
             'api_username', 'client_username', 'service_account', 'service_user', 'email', 'email_address'
        ]
        self.token_keywords = [
            'token', 'access_token', 'refresh_token', 'id_token', 'jwt', 'session_token', 'security_token',
            'api_token', 'auth_token', 'oauth_token', 'api_auth_token', 'api_token_key', 'auth_token_key',
            'oauth_token_key', 'api_key_token', 'access_token_key', 'security_token_key', 'session_key_token',
            'jwt_token', 'token_code', 'api_key_code', 'auth_key_code', 'oauth_key_code', 'api_secret_token',
            'access_secret_token', 'client_secret_token', 'service_secret_token', 'verification_token',
            'reset_token', 'confirmation_token', 'temp_token', 'qr_code_token', 'captcha_token', 'otp_token',
            'sms_token', 'email_token', '2fa_token', 'code_token', 'session_id', 'session_key', 'session_code'
        ]
        self.subkeywords = {
            'client_id': 'client id',
            'passcode': 'passcode'
        }
        self.used_values = set()  # Keep track of values already used
        self.extract_keywords()
        self.print_json_data()

    def extract_keywords(self):
        for subdomain in self.subdomains:
            url = f"http://{subdomain}"

            try:
                response = requests.get(url)
                if response.status_code == 200:
                    page_source = response.text

                    keywords = {
                        'subdomain': subdomain,
                        'tokens_list': [],
                        'keys_list': [],
                        'username_list': [],
                        'password_list': []
                    }

                    # Check for keywords in the page source

                    for kw in self.token_keywords:
                        match = re.search(rf'{kw}:\s*"?([^",\s]+)"?', page_source)
                        if match:
                            token_value = match.group(1)
                            if token_value not in self.used_values:
                                if kw in self.subkeywords:
                                    token_keyword = self.subkeywords[kw]
                                    token_value = {token_keyword: token_value}
                                else:
                                    token_value = {kw: token_value}
                                keywords['tokens_list'].append(token_value)
                                self.used_values.add(token_value)

                    for kw in self.key_keywords:
                        match = re.search(rf'{kw}:\s*"?([^",\s]+)"?', page_source)
                        if match:
                            key_value = match.group(1)
                            if key_value not in self.used_values:
                                if kw in self.subkeywords:
                                    key_keyword = self.subkeywords[kw]
                                    key_value = {key_keyword: key_value}
                                else:
                                    key_value = {kw: key_value}
                                keywords['keys_list'].append(key_value)
                                self.used_values.add(key_value)

                    for kw in self.username_keywords:
                        match = re.search(rf'{kw}:\s*"?([^",\s]+)"?', page_source)
                        if match:
                            username_value = match.group(1)
                            if username_value not in self.used_values:
                                if kw in self.subkeywords:
                                    username_keyword = self.subkeywords[kw]
                                    username_value = {username_keyword: username_value}
                                else:
                                    username_value = {kw: username_value}
                                if "email" in username_value and not self.is_valid_email(username_value["email"]):
                                    continue
                                keywords['username_list'].append(username_value)
                                self.used_values.add(list(username_value.values())[0])

                    for kw in self.password_keywords:
                        match = re.search(rf'{kw}:\s*"?([^",\s]+)"?', page_source)
                        if match:
                            password_value = match.group(1)
                            if password_value not in self.used_values:
                                if kw in self.subkeywords:
                                    password_keyword = self.subkeywords[kw]
                                    password_value = {password_keyword: password_value}
                                else:
                                    password_value = {kw: password_value}
                                keywords['password_list'].append(password_value)
                                self.used_values.add(list(password_value.values())[0])

                    self.results.append(keywords)

                elif response.status_code != 200:
                    print(f"Error connecting to {url}. Status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                print(f"Error connecting to {url}: {e}")

    def is_valid_email(self, email):
        # Use a regular expression to validate the email address
        pattern = r'^[\w+\-.]+@[a-z\d\-]+(\.[a-z]+)*\.[a-z]+$'
        return re.match(pattern, email) is not None
    
    def print_json_data(self):
        # Convert results to JSON format
        json_data = json.dumps(self.results, indent=4)
        print(json_data)