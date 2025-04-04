import unittest
import pandas as pd
import os
from datetime import datetime
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))
from security_analyzer import DataCleaner, DataIntegrator, ProcessTreeAnalyzer, SecurityEventAnalyzer

class TestSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        # Mock process events (matches the sample data exactly)
        self.process_data = pd.DataFrame({
            'process_id': [100, 2139, 2654, 3664, 3803],
            'parent_id': [0, 100, 2139, 2654, 3803],  # 3803 is a cycle (parent=itself)
            'start_time': ['2025-03-01 09:00:00', '2025-03-01 09:05:26', 
                          '2025-03-01 09:43:23', '2025-03-01 09:45:45', 
                          '2025-03-01 09:31:33'],
            'end_time': ['2025-03-01 10:00:00', '2025-03-01 10:56:46',
                        '2025-03-01 10:53:53', '2025-03-01 09:36:27',  # Invalid (end < start)
                        '2025-03-01 09:51:48'],
            'executable_path': [
                'C:/Windows/System32/explorer.exe',
                'C:/Windows/SysWOW64/svchost.exe',
                'C:/Program Files/winword.exe',
                'C:/Program Files/calc.exe',
                'C:/Windows/SysWOW64/explorer.exe'
            ],
            'user': ['SYSTEM', 'user1', 'johndoe', 'admin', 'johndoe']
        })

        # Mock network events (matches the sample data)
        self.network_data = pd.DataFrame({
            'process_id': [1188, 2923, 3615, 3762, 2022],
            'src_ip': ['74.229.195.161', '70.136.50.130', '87.92.160.5', 
                      '115.179.112.145', '154.62.61.44'],
            'dst_ip': ['247.21.49.181', '168.200.236.123', '173.4.34.6', 
                      '65.98.17.12', '220.66.192.94'],
            'src_port': [63688, 49147, 27975, 41616, 59744],
            'dst_port': [443, 8080, 80, 80, 80],
            'timestamp': ['2025-03-01 09:41:40', '2025-03-01 09:40:11',
                         '2025-03-01 09:35:51', '2025-03-01 09:03:52',
                         '2025-03-01 09:47:29'],
            'user': ['johndoe', 'user1', 'admin', 'user1', 'user1']
        })

        # Mock file events (matches the sample data)
        self.file_data = pd.DataFrame({
            'process_id': [5631, 2226, 9582, 3938, 9129, 3207],
            'file_path': [
                'C:/Program Files/config.ini',
                'C:/Users/JohnDoe/Desktop/log.txt',
                'C:/Users/JohnDoe/Desktop/readme.txt',
                'C:/Program Files/Common Files/log.txt',
                'C:/Windows/SysWOW64/readme.txt',
                'C:/Program Files/Common Files/report.docx'
            ],
            'operation': ['read', 'read', 'read', 'read', 'read', 'read'],
            'timestamp': [
                '2025-03-01 09:59:59', '2025-03-01 09:04:01',
                '2025-03-01 09:35:28', '2025-03-01 09:13:55',
                '2025-03-01 09:52:21', '2025-03-01 09:45:24'
            ],
            'user': ['admin', 'janedoe', 'user1', 'janedoe', 'janedoe', 'janedoe']
        })

        # Mock registry events (matches the sample data, including the malicious entry)
        self.registry_data = pd.DataFrame({
            'process_id': [9864, 1355, 3441, 2467, 4866, 1828, 4022, 6289, 9201],
            'registry_key': [
                'HKEY_LOCAL_MACHINE\\SOFTWARE/Microsoft/Office/16.0',
                'HKEY_LOCAL_MACHINE\\SOFTWARE/Microsoft/Windows NT/CurrentVersion',
                'HKEY_CURRENT_USER\\SOFTWARE/Google/Chrome',
                'HKEY_CURRENT_USER\\SOFTWARE/Microsoft/Office/16.0',
                'HKEY_CURRENT_USER\\SOFTWARE/Microsoft/Windows NT/CurrentVersion',
                'HKEY_LOCAL_MACHINE\\SOFTWARE/Microsoft/Windows NT/CurrentVersion',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_LOCAL_MACHINE\\SOFTWARE/Microsoft/Office/16.0',
                'HKEY_CURRENT_USER\\SOFTWARE/Oracle/Java'
            ],
            'operation': ['delete', 'modify', 'delete', 'create', 'modify',
                         'modify', 'create', 'create', 'delete'],
            'timestamp': [
                '2025-03-01 09:48:12', '2025-03-01 09:07:03',
                '2025-03-01 09:44:27', '2025-03-01 09:07:16',
                '2025-03-01 09:10:45', '2025-03-01 09:39:23',
                '2025-03-01 09:57:02', '2025-03-01 09:14:09',
                '2025-03-01 09:50:59'
            ],
            'value_name': [None, None, None, None, None, None, 'MaliciousApp', None, None],
            'value_data': [None, None, None, None, None, None, 'C:/Users/Admin/notepad.exe', None, None],
            'user': ['janedoe', 'johndoe', 'janedoe', 'johndoe', 'janedoe', 'admin', 'admin', 'user1', 'admin']
        })

    def test_data_cleaning(self):
        """Test cleaning logic for all event types."""
        cleaned_process = DataCleaner.clean_process_events(self.process_data)
        self.assertEqual(len(cleaned_process), 4)  # Removes self-parenting process (3803)

        cleaned_network = DataCleaner.clean_network_events(self.network_data)
        self.assertEqual(len(cleaned_network), 5)  # All sample network events are valid

        cleaned_file = DataCleaner.clean_file_events(self.file_data)
        self.assertEqual(len(cleaned_file), 6)  # All sample file events are valid

        cleaned_registry = DataCleaner.clean_registry_events(self.registry_data)
        self.assertEqual(len(cleaned_registry), 9)  # All sample registry events are valid
        self.assertEqual(cleaned_registry.iloc[6]['value_name'], 'MaliciousApp')  # Verify malicious entry

    def test_process_tree_analysis(self):
        """Test process tree building and reporting."""
        cleaned_process = DataCleaner.clean_process_events(self.process_data)
        analyzer = ProcessTreeAnalyzer(cleaned_process)
        
        tree = analyzer.get_process_tree(100)  # Root process (explorer.exe)
        self.assertEqual(tree['process_id'], 100)
        self.assertEqual(len(tree['children']), 1)  # Should have 1 child (2139: svchost.exe)

        markdown = analyzer.tree_to_markdown(tree)
        self.assertIn("Process ID: 100", markdown)
        self.assertIn("explorer.exe", markdown)

    def test_data_integration(self):
        """Test unified data structure."""
        cleaned_process = DataCleaner.clean_process_events(self.process_data)
        cleaned_network = DataCleaner.clean_network_events(self.network_data)
        cleaned_file = DataCleaner.clean_file_events(self.file_data)
        cleaned_registry = DataCleaner.clean_registry_events(self.registry_data)
        
        unified = DataIntegrator.integrate_data(
            cleaned_process, cleaned_network, cleaned_file, cleaned_registry
        )
        self.assertEqual(len(unified), 24)  
        self.assertEqual(len(unified[unified['event_type'] == 'registry']), 9)

    def test_malicious_process_analysis(self):
        """Test end-to-end analysis (using process 4022, which has the malicious registry entry)."""
        analyzer = SecurityEventAnalyzer("dummy_path")  
        
        # Inject mocked data (bypassing load_data())
        analyzer.process_df = DataCleaner.clean_process_events(self.process_data)
        analyzer.network_df = DataCleaner.clean_network_events(self.network_data)
        analyzer.file_df = DataCleaner.clean_file_events(self.file_data)
        analyzer.registry_df = DataCleaner.clean_registry_events(self.registry_data)
        analyzer.integrate_data()
        
        analyzer.analyze_malicious_process(4022)
        
        self.assertTrue(os.path.exists("reports/process_tree_4022.md"))
        os.remove("reports/process_tree_4022.md")

if __name__ == '__main__':
    unittest.main()