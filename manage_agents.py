#!/usr/bin/env python3
"""
NightAction Agent Management Utility
Tool for managing authentication codes and agents
"""

import sqlite3
import hashlib
from datetime import datetime

class AgentManager:
    def __init__(self, db_path='nightaction.db'):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                codename TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _hash_code(self, code_words):
        """Hash the 4-word code for secure storage"""
        code_string = ' '.join(code_words).upper()
        return hashlib.sha256(code_string.encode()).hexdigest()

    def add_agent(self, code_words, codename):
        """Add a new agent"""
        if len(code_words) != 4:
            print("[-] Error: Code must be exactly 4 words")
            return False

        code_hash = self._hash_code(code_words)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO agents (code_hash, codename) VALUES (?, ?)',
                (code_hash, codename)
            )
            conn.commit()
            conn.close()
            print(f"[+] Agent added successfully: {codename}")
            print(f"    Code: {' '.join(code_words)}")
            return True
        except sqlite3.IntegrityError:
            print(f"[-] Error: This code already exists in the database")
            return False

    def list_agents(self):
        """List all agents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, codename, active, created_at, last_used
            FROM agents
            ORDER BY id
        ''')
        agents = cursor.fetchall()
        conn.close()

        if not agents:
            print("\n[*] No agents in database")
            return

        print("\n" + "="*80)
        print(f"{'ID':<5} {'CODENAME':<20} {'STATUS':<10} {'CREATED':<20} {'LAST USED':<20}")
        print("="*80)

        for agent in agents:
            agent_id, codename, active, created_at, last_used = agent
            status = "ACTIVE" if active else "INACTIVE"
            last_used_str = last_used if last_used else "Never"

            print(f"{agent_id:<5} {codename:<20} {status:<10} {created_at:<20} {last_used_str:<20}")

        print("="*80 + "\n")

    def deactivate_agent(self, agent_id):
        """Deactivate an agent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT codename FROM agents WHERE id = ?', (agent_id,))
        result = cursor.fetchone()

        if not result:
            print(f"[-] Agent with ID {agent_id} not found")
            conn.close()
            return False

        cursor.execute('UPDATE agents SET active = 0 WHERE id = ?', (agent_id,))
        conn.commit()
        conn.close()

        print(f"[+] Agent deactivated: {result[0]} (ID: {agent_id})")
        return True

    def activate_agent(self, agent_id):
        """Activate an agent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT codename FROM agents WHERE id = ?', (agent_id,))
        result = cursor.fetchone()

        if not result:
            print(f"[-] Agent with ID {agent_id} not found")
            conn.close()
            return False

        cursor.execute('UPDATE agents SET active = 1 WHERE id = ?', (agent_id,))
        conn.commit()
        conn.close()

        print(f"[+] Agent activated: {result[0]} (ID: {agent_id})")
        return True

    def delete_agent(self, agent_id):
        """Delete an agent permanently"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT codename FROM agents WHERE id = ?', (agent_id,))
        result = cursor.fetchone()

        if not result:
            print(f"[-] Agent with ID {agent_id} not found")
            conn.close()
            return False

        confirm = input(f"[!] Are you sure you want to delete agent '{result[0]}'? (yes/no): ")
        if confirm.lower() != 'yes':
            print("[*] Deletion cancelled")
            conn.close()
            return False

        cursor.execute('DELETE FROM agents WHERE id = ?', (agent_id,))
        conn.commit()
        conn.close()

        print(f"[+] Agent deleted: {result[0]} (ID: {agent_id})")
        return True

def print_menu():
    """Print the main menu"""
    print("""
╔═══════════════════════════════════════════╗
║      NIGHTACTION AGENT MANAGEMENT         ║
╚═══════════════════════════════════════════╝

1. Add new agent
2. List all agents
3. Deactivate agent
4. Activate agent
5. Delete agent
6. Exit
""")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='NightAction Agent Management')
    parser.add_argument('--db', default='nightaction.db', help='Database file path')
    args = parser.parse_args()

    manager = AgentManager(db_path=args.db)

    while True:
        print_menu()
        choice = input("Select option: ").strip()

        if choice == '1':
            print("\n[*] Add New Agent")
            codename = input("Codename: ").strip().upper()
            if not codename:
                print("[-] Codename cannot be empty")
                continue

            print("Enter 4-word authentication code:")
            code_words = []
            for i in range(1, 5):
                word = input(f"  Word {i}: ").strip()
                if not word:
                    print("[-] Word cannot be empty")
                    break
                code_words.append(word.upper())

            if len(code_words) == 4:
                manager.add_agent(code_words, codename)

        elif choice == '2':
            manager.list_agents()

        elif choice == '3':
            manager.list_agents()
            agent_id = input("Enter agent ID to deactivate: ").strip()
            try:
                manager.deactivate_agent(int(agent_id))
            except ValueError:
                print("[-] Invalid agent ID")

        elif choice == '4':
            manager.list_agents()
            agent_id = input("Enter agent ID to activate: ").strip()
            try:
                manager.activate_agent(int(agent_id))
            except ValueError:
                print("[-] Invalid agent ID")

        elif choice == '5':
            manager.list_agents()
            agent_id = input("Enter agent ID to delete: ").strip()
            try:
                manager.delete_agent(int(agent_id))
            except ValueError:
                print("[-] Invalid agent ID")

        elif choice == '6':
            print("\n[*] Goodbye")
            break

        else:
            print("[-] Invalid option")

if __name__ == '__main__':
    main()
