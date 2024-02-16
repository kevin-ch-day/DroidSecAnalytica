# intent_filters_analysis.py

from typing import Dict, List
from database import DB_Other

def is_unusual_intent(action: str, unusual_intents: List[str]) -> bool:
    """Check if an intent action is unusual or high-risk."""
    return action in unusual_intents

def is_missing_common_intent(action: str, component_type: str, common_intents: List[str]) -> bool:
    """Check if a common intent is missing in certain types of components."""
    return (
        component_type == 'some_specific_component_type' and
        action not in common_intents
    )

def intent_filter_analysis(intent_filter: Dict, manifest_data: Dict, unusual_intents: List[str], common_intents: List[str]) -> bool:
    """Analyze an intent filter for unusual or missing intents."""
    intent_actions = intent_filter.get('actions', [])
    for action in intent_actions:
        if is_unusual_intent(action, unusual_intents) or is_missing_common_intent(action, intent_filter.get('component_type'), common_intents):
            return True
    return False

def analyze_intent_filters(manifest_data: Dict) -> List[str]:
    """Analyze intent filters in manifest data for suspicious filters."""
    unusual_intents = DB_Other.get_intent_filters(is_unusual=True)
    common_intents = DB_Other.get_intent_filters(is_unusual=False)
    
    suspicious_filters = []
    for component in manifest_data.get('activity', []) + manifest_data.get('service', []):
        intent_filters = component.get('intent-filters', [])
        for intent_filter in intent_filters:
            if intent_filter_analysis(intent_filter, manifest_data, unusual_intents, common_intents):
                suspicious_filters.append(intent_filter)
    return suspicious_filters

def analyze_custom_intents(manifest_data: Dict, custom_intents: List[str]) -> List[str]:
    """Analyze intent filters for custom intents."""
    suspicious_filters = []
    for component in manifest_data.get('activity', []) + manifest_data.get('service', []):
        intent_filters = component.get('intent-filters', [])
        for intent_filter in intent_filters:
            intent_actions = intent_filter.get('actions', [])
            for action in intent_actions:
                if action in custom_intents:
                    suspicious_filters.append(intent_filter)
    return suspicious_filters

def analyze_broadcast_receivers(manifest_data: Dict) -> List[str]:
    """Analyze broadcast receivers for sensitive intent actions."""
    sensitive_actions = ['android.intent.action.BOOT_COMPLETED', 'android.provider.Telephony.SMS_RECEIVED']
    suspicious_receivers = []
    for receiver in manifest_data.get('receiver', []):
        intent_filters = receiver.get('intent-filters', [])
        for intent_filter in intent_filters:
            intent_actions = intent_filter.get('actions', [])
            for action in intent_actions:
                if action in sensitive_actions:
                    suspicious_receivers.append(receiver['android:name'])
    return suspicious_receivers
