import json
from typing import List, Dict, Any

class IntentFilterADT:
    """Class to manage intent filters for Activities and Receivers."""

    def __init__(self):
        """Initializes the IntentFilterADT class."""
        self.valid_entity_types = {'Activities', 'Receivers'}
        self.data = {entity_type: {} for entity_type in self.valid_entity_types}

    def _initialize_entity(self, entity_type: str, entity: str):
        """Initializes the entity if not already present."""
        if entity not in self.data[entity_type]:
            self.data[entity_type][entity] = {'action': [], 'category': []}

    def add_intent_filter(self, entity_type: str, entity: str, action: List[str], category: List[str]):
        """Adds an intent filter to the specified entity."""
        if entity_type not in self.valid_entity_types:
            raise ValueError(f"Invalid entity type: {entity_type}")

        if not isinstance(action, list) or not isinstance(category, list):
            raise TypeError("Action and category must be lists")

        self._initialize_entity(entity_type, entity)
        self.data[entity_type][entity]['action'].extend(action)
        self.data[entity_type][entity]['category'].extend(category)

    def get_intent_filter(self, entity_type: str, entity: str) -> Dict[str, Any]:
        """Retrieves the intent filter for a specific entity."""
        return self.data.get(entity_type, {}).get(entity, {})

    def get_all_intent_filters(self) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
        """Returns all intent filters."""
        return self.data

    def find_entities_by_action_or_category(self, search_term: str) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
        """Finds entities by action or category matching the search term."""
        results = {}
        for entity_type, entities in self.data.items():
            for entity, details in entities.items():
                if search_term in details['action'] or search_term in details['category']:
                    results.setdefault(entity_type, {})[entity] = details
        return results

    def __str__(self) -> str:
        """Returns a string representation of the intent filters data."""
        return json.dumps(self.data, indent=4)
