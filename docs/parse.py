# pip install ramlfications
import ramlfications
RAML_FILE = "./nethsm-api.raml"
CONFIG_FILE = "./config.ini"
api = ramlfications.parse(RAML_FILE, CONFIG_FILE)
