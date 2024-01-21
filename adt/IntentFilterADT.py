import json

class IntentFilterADT:
    def __init__(self):
        self.valid_entity_types = {'Activities', 'Receivers'}
        self.data = {entity_type: {} for entity_type in self.valid_entity_types}

    def add_intent_filter(self, entity_type, entity, action, category):
        if entity_type not in self.valid_entity_types:
            raise ValueError(f"Invalid entity type: {entity_type}")

        if not isinstance(action, list) or not isinstance(category, list):
            raise TypeError("Action and category must be lists")

        if entity_type in self.data:
            if entity not in self.data[entity_type]:
                self.data[entity_type][entity] = {'action': [], 'category': []}
            
            self.data[entity_type][entity]['action'].extend(action)
            self.data[entity_type][entity]['category'].extend(category)

    def get_intent_filter(self, entity_type, entity):
        return self.data.get(entity_type, {}).get(entity, {})

    def get_all_intent_filters(self):
        return self.data

    def find_entities_by_action_or_category(self, search_term):
        results = {}
        for entity_type, entities in self.data.items():
            for entity, details in entities.items():
                if search_term in details['action'] or search_term in details['category']:
                    results.setdefault(entity_type, {})[entity] = details
        return results

    def __str__(self):
        return json.dumps(self.data, indent=4)
