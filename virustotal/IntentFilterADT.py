import json
import re
from typing import List, Dict, Any

class IntentFilterADT:
    def __init__(self, valid_entity_types=None):
        if valid_entity_types is None:
            valid_entity_types = {'Activities', 'Services', 'Receivers'}
        self.valid_entity_types = valid_entity_types
        self.data = {entity_type: {} for entity_type in self.valid_entity_types}

    def _initialize_entity(self, entity_type: str, entity: str):
        if entity not in self.data[entity_type]:
            self.data[entity_type][entity] = {'action': [], 'category': []}

    def add_intent_filter(self, entity_type: str, entity: str, action: List[str], category: List[str]):
        if entity_type not in self.valid_entity_types:
            raise ValueError(f"Invalid entity type: {entity_type}")

        if not all(isinstance(a, str) for a in action) or not all(isinstance(c, str) for c in category):
            raise TypeError("Actions and categories must be lists of strings")

        self._initialize_entity(entity_type, entity)
        self.data[entity_type][entity]['action'].extend(action)
        self.data[entity_type][entity]['category'].extend(category)

    def get_intent_filter(self, entity_type: str, entity: str) -> Dict[str, Any]:
        return self.data.get(entity_type, {}).get(entity, {})

    def get_all_intent_filters(self) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
        return self.data

    def find_entities_by_action_or_category(self, search_term: str, use_regex: bool = False) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
        results = {}
        for entity_type, entities in self.data.items():
            for entity, details in entities.items():
                if (use_regex and (re.search(search_term, ' '.join(details['action'])) or re.search(search_term, ' '.join(details['category'])))) \
                   or (not use_regex and (search_term in details['action'] or search_term in details['category'])):
                    results.setdefault(entity_type, {})[entity] = details
        return results

    def __str__(self) -> str:
        return json.dumps(self.data, indent=4)
