# manifest_analysis.py

import logging
import os
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List

from utils import load_data
from . import intent_filters_analysis, save_permissions

# Constants
METADATA_ELEMENTS = ["uses-permission", "application", "activity", "service",
                     "provider", "receiver", "uses-library", "uses-feature",
                     "instrumentation", "uses-sdk", "meta-data", "permission"]

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def parse_xml(manifest_path: str) -> ET.Element:
    manifest_content = load_data.read_file(manifest_path)
    return ET.ElementTree(ET.fromstring(manifest_content)).getroot()

def extract_detailed_attributes(element: ET.Element) -> Dict[str, str]:
    """ Extracts detailed attributes from an XML element. """
    attributes = {}
    for attribute in element.attrib:
        attributes[attribute] = element.get(attribute)
    return attributes

def analyze_element(root: ET.Element, element_name: str) -> List[Dict[str, str]]:
    """ Analyzes a specific element in the XML and returns its data. """
    element_data = []
    for element in root.iter(element_name):
        data = extract_detailed_attributes(element)
        element_data.append(data)
    return element_data

def heuristic_analysis(manifest_data: Dict) -> Dict:
    analysis_results = {
        'overprivileged': False,
        'overprivileged_score': 0,
        'sensitive_permissions': [],
        'exposed_components': [],
        'unusual_activities_services': [],
        'suspicious_intent_filters': [],
        'risky_permission_combinations': False,
        'hidden_components': [],
        'network_related_permissions': [],
        'custom_intent_filter_analysis_result': []  # Add a new result key for custom intent filter analysis
    }

    # Heuristic 1: Identify Overprivileged Apps
    overprivileged_results = save_permissions.identify_overprivileged_apps(manifest_data)
    analysis_results.update(overprivileged_results)

    # Heuristic 2: Check for Uncommon or Sensitive Permissions
    analysis_results['sensitive_permissions'] = save_permissions.check_sensitive_permissions(manifest_data)

    # Heuristic 3: Analyze Component Exposure
    exposed_components = []
    for component in manifest_data.get('activity', []) + manifest_data.get('service', []):
        if component.get('android:exported', 'false') == 'true' and 'android:permission' not in component:
            exposed_components.append(component['android:name'])
    
    analysis_results['exposed_components'] = exposed_components

    # Heuristic 4: Check for Unusual Activities or Services
    analysis_results['unusual_activities_services'] = check_unusual_activities_services(manifest_data)

    # Heuristic 5: Analyze Intent Filters
    analysis_results['suspicious_intent_filters'] = intent_filters_analysis.analyze_intent_filters(manifest_data)
    analysis_results['custom_intent_filter_analysis_result'] = intent_filters_analysis.custom_intent_filter_analysis(manifest_data)

    # Heuristic 6: Network-related Permissions
    analysis_results['network_related_permissions'] = save_permissions.check_network_permissions(manifest_data)
    return analysis_results

def check_unusual_activities_services(manifest_data: Dict) -> List[str]:
    unusual_components = []

    # Define known common and malicious patterns
    known_common_components = {'com.example.StandardActivity', 'com.example.StandardService'}
    known_malicious_patterns = {'com.malicious.HiddenActivity', 'com.malicious.SpyService'}

    for activity in manifest_data.get('activity', []):
        activity_name = activity.get('android:name')

        # Check if the activity matches known malicious patterns
        if activity_name in known_malicious_patterns:
            unusual_components.append(activity_name)

        # If not a known common component, perform behavioral analysis
        elif activity_name not in known_common_components:
            if is_behaviorally_suspicious(activity, manifest_data):
                unusual_components.append(activity_name)

    return unusual_components

def is_behaviorally_suspicious(component: Dict, manifest_data: Dict) -> bool:
    # Check for exported components without proper security measures
    exported = component.get('android:exported', 'false')
    if exported == 'true' and 'android:permission' not in component:
        return True

    # Check for unusual intent filters
    intent_filters = component.get('intent-filters', [])
    if has_unusual_intent_filters(intent_filters, manifest_data):
        return True

    # Check for high-risk intent actions
    high_risk_actions = ['android.intent.action.BOOT_COMPLETED', 'android.provider.Telephony.SMS_RECEIVED']
    if has_high_risk_intent_actions(intent_filters, high_risk_actions):
        return True

    return False

def has_unusual_intent_filters(intent_filters: List[Dict], manifest_data: Dict) -> bool:
    # Define a list of unusual intent actions or categories
    unusual_intent_actions = ['com.example.UNUSUAL_ACTION', 'com.example.ANOTHER_UNUSUAL_ACTION']
    unusual_intent_categories = ['com.example.UNUSUAL_CATEGORY']

    for intent_filter in intent_filters:
        actions = intent_filter.get('actions', [])
        categories = intent_filter.get('categories', [])

        # Check if any intent action or category is unusual
        if any(action in unusual_intent_actions for action in actions) or any(category in unusual_intent_categories for category in categories):
            return True

    return False

def has_high_risk_intent_actions(intent_filters: List[Dict], high_risk_actions: List[str]) -> bool:
    for intent_filter in intent_filters:
        actions = intent_filter.get('actions', [])

        # Check if any high-risk intent action is present
        if any(action in high_risk_actions for action in actions):
            return True

    return False

def risk_scoring_system(analysis_results: Dict) -> int:
    risk_score = 0

    # Heuristic 1: Identify Overprivileged Apps
    if analysis_results['overprivileged']:
        risk_score += analysis_results['overprivileged_score']

    # Heuristic 2: Check for Uncommon or Sensitive Permissions
    risk_score += len(analysis_results['sensitive_permissions']) * 10  # Increase the risk score for sensitive permissions

    # Heuristic 3: Analyze Component Exposure
    risk_score += len(analysis_results['exposed_components']) * 5  # Increase the risk score for exposed components

    # Heuristic 4: Analyze Suspicious Intent Filters
    risk_score += len(analysis_results['suspicious_intent_filters']) * 10  # Increase the risk score for suspicious intent filters

    custom_intent_filter_analysis_result = analysis_results.get('custom_intent_filter_analysis_result', [])
    risk_score += len(custom_intent_filter_analysis_result) * 15  # Adjust the score as needed for custom intent filter analysis

    return risk_score

def analyze_android_manifest(manifest_path: str) -> Optional[Dict]:
    analysis_results = {
        'manifest_data': None,
        'heuristic_results': None,
        'risk_score': None
    }

    try:
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f'AndroidManifest.xml not found at {manifest_path}')

        root = parse_xml(manifest_path)
        manifest_data = {element: analyze_element(root, element) for element in METADATA_ELEMENTS}
        analysis_results['manifest_data'] = manifest_data

        heuristic_results = heuristic_analysis(manifest_data)
        analysis_results['heuristic_results'] = heuristic_results

        risk_score = risk_scoring_system(heuristic_results)
        analysis_results['risk_score'] = risk_score

        logging.info('AndroidManifest.xml analysis completed.')
        return analysis_results
    
    except ET.ParseError as e:
        logging.error(f'XML parsing error: {e}')
        return None
    
    except FileNotFoundError as e:
        logging.error(e)
        return None

    except Exception as e:
        logging.error(f'Error analyzing AndroidManifest.xml: {e}')
        return None