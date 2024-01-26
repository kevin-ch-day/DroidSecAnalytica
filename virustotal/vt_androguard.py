from utils import logging_utils
from . import AndroguardADT
from . import vt_androguard_parser
from . import display_androguard_data

def parse_androguard_data(attributes):
    try:
        data = attributes.get('androguard', None)
        if not data:
            return None

        androguard_data = AndroguardADT.AndroguardADT()
        vt_androguard_parser.parse_basic_data(androguard_data, data)
        vt_androguard_parser.parse_permissions(androguard_data, data)
        vt_androguard_parser.parse_certificate_data(androguard_data, data)
        vt_androguard_parser.parse_intent_filters(androguard_data, data)
        return androguard_data

    except Exception as e:
        logging_utils.log_error(f"Error parsing Androguard data: {str(e)}")
        return None
    
def display_attributes(attributes):
    try:
        androguard_data = parse_androguard_data(attributes)
        if androguard_data:
            display_androguard_data.display_main_activity(androguard_data)
            display_androguard_data.display_sections(androguard_data)
            display_androguard_data.display_certificate_details(androguard_data)
            display_androguard_data.display_permissions(androguard_data.get_permissions())
            display_androguard_data.display_intent_filters(androguard_data)
            pass
        
        else:
            logging_utils.log_error("Error: no androguard data found.")

    except Exception as e:
        logging_utils.log_error(f"Error processing response attributes: {str(e)}")