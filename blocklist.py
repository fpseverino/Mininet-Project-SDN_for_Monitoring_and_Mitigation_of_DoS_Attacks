import sqlite3

class Blocklist():
    def __init__(self, filename=None):
        '''
        Class to keep track of the blocked flows/hosts using SQLite database \\
        Database contains: \\
            - int_blocked = flows/hosts blocked by PolicyMaker (block_type='internal')
            - ext_blocked = flows/hosts blocked by admins at startup or by request (block_type='external')
        '''
        self.db_path = filename if filename else ":memory:"
        self._init_database()
        
    def _init_database(self):
        '''Initialize SQLite database with required tables'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create unified table for all blocked entries
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dpid TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT,
                block_type TEXT NOT NULL DEFAULT 'internal',
                UNIQUE(dpid, source, destination, block_type)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def add(self, dpid, source, destination=None, block_type="internal"):
        '''Add entry to blocked list in database'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO blocked_entries (dpid, source, destination, block_type)
                VALUES (?, ?, ?, ?)
            ''', (dpid, source, destination, block_type))
            conn.commit()
        finally:
            conn.close()
    
    def remove(self, dpid, source, destination=None, block_type="internal"):
        '''Remove entry from blocked list in database'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if destination is None:
                cursor.execute('''
                    DELETE FROM blocked_entries 
                    WHERE dpid = ? AND source = ? AND destination IS NULL AND block_type = ?
                ''', (dpid, source, block_type))
            else:
                cursor.execute('''
                    DELETE FROM blocked_entries 
                    WHERE dpid = ? AND source = ? AND destination = ? AND block_type = ?
                ''', (dpid, source, destination, block_type))
            conn.commit()
        finally:
            conn.close()

    def values(self, block_type=None):
        '''Return all blocked entries (internal and/or external) as a set'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if block_type:
                cursor.execute('SELECT dpid, source, destination FROM blocked_entries WHERE block_type = ?', (block_type,))
            else:
                cursor.execute('SELECT dpid, source, destination FROM blocked_entries')
            rows = cursor.fetchall()
            
            result = set()
            for row in rows:
                dpid, source, destination = row
                # Convert empty string to None for destination
                destination = destination if destination else None
                result.add((dpid, source, destination))
            
            return result
        finally:
            conn.close()
