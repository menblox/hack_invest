import json
import os
from typing import List, Dict, Optional

class JSONLocationStorage:
    def __init__(self, file_path: str = "locations.json"):
        self.file_path = file_path
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        if not os.path.exists(self.file_path):
            with open(self.file_path, 'w') as f:
                json.dump([], f)

    def _read_locations(self) -> List[Dict]:
        try:
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write_locations(self, locations: List[Dict]):
        with open(self.file_path, 'w') as f:
            json.dump(locations, f, indent=2, ensure_ascii=False)

    def get_user_locations(self, user_id: int) -> List[Dict]:
        locations = self._read_locations()
        return [loc for loc in locations if loc.get('user_id') == user_id]

    def create_location(self, location_data: Dict) -> Dict:
        locations = self._read_locations()
        
        # Генерируем ID
        if locations:
            new_id = max(loc['id'] for loc in locations) + 1
        else:
            new_id = 1
            
        location_data['id'] = new_id
        locations.append(location_data)
        self._write_locations(locations)
        
        return location_data

    def update_location_travel_time(self, location_id: int, travel_time: str, user_id: int) -> Optional[Dict]:
        locations = self._read_locations()
        
        for location in locations:
            if location['id'] == location_id and location['user_id'] == user_id:
                location['travel_time'] = travel_time
                self._write_locations(locations)
                return location
                
        return None

    def delete_location(self, location_id: int, user_id: int) -> bool:
        locations = self._read_locations()
        
        for i, location in enumerate(locations):
            if location['id'] == location_id and location['user_id'] == user_id:
                locations.pop(i)
                self._write_locations(locations)
                return True
                
        return False

# Глобальный экземпляр хранилища
location_storage = JSONLocationStorage()