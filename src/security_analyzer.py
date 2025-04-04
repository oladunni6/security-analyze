import pandas as pd
from datetime import datetime
import logging
from typing import Dict, List, Optional, Union
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataCleaner:
    """Handles cleaning and normalization of all event types."""
    
    @staticmethod
    def clean_process_events(df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize process events data."""
        logger.info("Cleaning process events")
        
        # Handle missing values
        df = df.dropna(subset=['process_id', 'executable_path', 'user'])
        
        # Standardize datetime formats
        for col in ['start_time', 'end_time']:
            df[col] = pd.to_datetime(df[col], errors='coerce')
            df = df.dropna(subset=[col])
        
        # Remove process cycles (where process is its own parent)
        df = df[df['process_id'] != df['parent_id']]
        
        # Fix invalid end times (end before start)
        invalid_end = df['end_time'] < df['start_time']
        df.loc[invalid_end, 'end_time'] = df.loc[invalid_end, 'start_time'] + pd.Timedelta(minutes=1)
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['process_id', 'start_time', 'executable_path'])
        
        return df
    
    @staticmethod
    def clean_network_events(df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize network events data."""
        logger.info("Cleaning network events")
        
        # Handle missing values
        df = df.dropna(subset=['process_id', 'dst_ip', 'timestamp'])
        
        # Standardize datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        
        # Handle IP addresses
        df['src_ip'] = df['src_ip'].apply(lambda x: x if x and x != '###CORRUPT###' else None)
        df['dst_ip'] = df['dst_ip'].apply(lambda x: None if x == '###CORRUPT###' else x)
        
        # Validate ports
        for port_col in ['src_port', 'dst_port']:
            df[port_col] = pd.to_numeric(df[port_col], errors='coerce')
            df = df[(df[port_col] >= 0) & (df[port_col] <= 65535)]
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['process_id', 'timestamp', 'dst_ip', 'dst_port'])
        
        return df
    
    @staticmethod
    def clean_file_events(df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize file events data."""
        logger.info("Cleaning file events")
        
        # Handle missing values
        df = df.dropna(subset=['process_id', 'file_path', 'timestamp'])
        
        # Standardize datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        
        # Clean operation field (handle numeric values)
        if 'operation' in df.columns:
            df['operation'] = df['operation'].astype(str).apply(
                lambda x: x.lower() if x and x != '###corrupt###' else None
            )
        
        # Standardize file paths
        df['file_path'] = df['file_path'].str.replace('\\', '/')
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['process_id', 'timestamp', 'file_path'])
        
        return df
    
    @staticmethod
    def clean_registry_events(df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize registry events data."""
        logger.info("Cleaning registry events")
        
        # Handle missing values
        df = df.dropna(subset=['process_id', 'registry_key', 'timestamp', 'operation'])
        
        # Standardize datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        
        # Clean operation field
        df['operation'] = df['operation'].apply(
            lambda x: x.lower() if x and x != '###CORRUPT###' else None
        )
        
        # Standardize registry key paths
        df['registry_key'] = df['registry_key'].str.replace('/', '\\')
        
        # Clean value data
        for col in ['value_name', 'value_data']:
            if col in df.columns:
                df[col] = df[col].replace({
                    '###CORRUPT###': None,
                    'None': None,
                    'null': None
                })
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['process_id', 'timestamp', 'registry_key'])
        
        return df

class DataIntegrator:
    """Handles integration of all event types into a unified structure."""
    
    @staticmethod
    def integrate_data(
        process_df: pd.DataFrame,
        network_df: pd.DataFrame,
        file_df: pd.DataFrame,
        registry_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Integrate all event types into a unified structure."""
        logger.info("Integrating data into unified structure")
        
        # Add event type identifiers
        process_df['event_type'] = 'process'
        network_df['event_type'] = 'network'
        file_df['event_type'] = 'file'
        registry_df['event_type'] = 'registry'
        
        # Standardize timestamp column names
        process_df['event_time'] = process_df['start_time']
        network_df.rename(columns={'timestamp': 'event_time'}, inplace=True)
        file_df.rename(columns={'timestamp': 'event_time'}, inplace=True)
        registry_df.rename(columns={'timestamp': 'event_time'}, inplace=True)
        
        # Concatenate all dataframes
        unified_df = pd.concat([
            process_df[['process_id', 'event_type', 'event_time', 'user', 'executable_path']],
            network_df[['process_id', 'event_type', 'event_time', 'user', 'src_ip', 'dst_ip', 'src_port', 'dst_port']],
            file_df[['process_id', 'event_type', 'event_time', 'user', 'file_path', 'operation']],
            registry_df[['process_id', 'event_type', 'event_time', 'user', 'registry_key', 'operation', 'value_name', 'value_data']]
        ], ignore_index=True)
        
        return unified_df

class ProcessTreeAnalyzer:
    """Analyzes process trees and generates reports."""
    
    def __init__(self, process_df: pd.DataFrame):
        self.process_df = process_df
        self.process_tree = {}
        self.visited_pids = set()  # Track visited PIDs to detect cycles
        self._build_process_tree()
    
    def _build_process_tree(self):
        """Build a dictionary representing the process tree."""
        for _, row in self.process_df.iterrows():
            pid = row['process_id']
            parent_id = row['parent_id']
            
            if pid not in self.process_tree:
                self.process_tree[pid] = {
                    'parent_id': parent_id,
                    'children': [],
                    'details': row.to_dict()
                }
            
            # Add to parent's children list
            if parent_id in self.process_tree:
                if pid not in self.process_tree[parent_id]['children']:
                    self.process_tree[parent_id]['children'].append(pid)
            elif parent_id != 0:  # 0 is typically the system/root parent
                logger.warning(f"Parent process {parent_id} not found for child {pid}")
    
    def get_process_tree(self, root_pid: int, max_depth: int = 5, current_depth: int = 0) -> Dict:
        """Get the process tree starting from a root PID with cycle detection."""
        if current_depth >= max_depth:
            return {
                'process_id': root_pid,
                'warning': f"Max depth {max_depth} reached"
            }
        
        if root_pid not in self.process_tree:
            return {}
        
        if root_pid in self.visited_pids:
            return {
                'process_id': root_pid,
                'warning': "Cycle detected"
            }
        
        self.visited_pids.add(root_pid)
        
        tree = {
            'process_id': root_pid,
            'details': self.process_tree[root_pid]['details'],
            'children': []
        }
        
        for child_pid in self.process_tree[root_pid]['children']:
            tree['children'].append(
                self.get_process_tree(child_pid, max_depth, current_depth + 1)
            )
        
        return tree
    
    @staticmethod
    def tree_to_markdown(tree: Dict, level: int = 0) -> str:
        """Convert process tree to Markdown format with cycle warnings."""
        if not tree:
            return ""
        
        indent = "  " * level
        markdown = f"{indent}- Process ID: {tree['process_id']}\n"
        
        if 'warning' in tree:
            markdown += f"{indent}  - WARNING: {tree['warning']}\n"
            return markdown
        
        markdown += f"{indent}  - Executable: {tree['details']['executable_path']}\n"
        markdown += f"{indent}  - User: {tree['details']['user']}\n"
        markdown += f"{indent}  - Start Time: {tree['details']['start_time']}\n"
        
        if tree['children']:
            markdown += f"{indent}  - Children:\n"
            for child in tree['children']:
                markdown += ProcessTreeAnalyzer.tree_to_markdown(child, level + 2)
        
        return markdown

class SecurityEventAnalyzer:
    """Main class for security event analysis."""
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.process_df = None
        self.network_df = None
        self.file_df = None
        self.registry_df = None
        self.unified_df = None
    
    def load_data(self):
        """Load data from CSV files in the external datasets directory."""
        logger.info(f"Loading data from {self.data_dir}")
        
        try:
            # Construct paths to the dataset files
            self.process_df = pd.read_csv(os.path.join(self.data_dir, "process_events.csv"))
            self.network_df = pd.read_csv(os.path.join(self.data_dir, "network_events.csv"))
            self.file_df = pd.read_csv(os.path.join(self.data_dir, "file_events.csv"))
            self.registry_df = pd.read_csv(os.path.join(self.data_dir, "registry_events.csv"))
            logger.info("Data loaded successfully")
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
    
    def clean_data(self):
        """Clean all dataframes."""
        if self.process_df is not None:
            self.process_df = DataCleaner.clean_process_events(self.process_df)
        if self.network_df is not None:
            self.network_df = DataCleaner.clean_network_events(self.network_df)
        if self.file_df is not None:
            self.file_df = DataCleaner.clean_file_events(self.file_df)
        if self.registry_df is not None:
            self.registry_df = DataCleaner.clean_registry_events(self.registry_df)
    
    def integrate_data(self):
        """Integrate all data into a unified structure."""
        if (self.process_df is not None and self.network_df is not None and 
            self.file_df is not None and self.registry_df is not None):
            self.unified_df = DataIntegrator.integrate_data(
                self.process_df, self.network_df, self.file_df, self.registry_df
            )
    
    def analyze_malicious_process(self, pid: int = 15150):
        """Analyze and report on a malicious process."""
        if self.process_df is None:
            logger.error("Process data not loaded")
            return
        
        analyzer = ProcessTreeAnalyzer(self.process_df)
        process_tree = analyzer.get_process_tree(pid)
        
        # Generate markdown report
        markdown_report = f"# Process Tree Analysis for Malicious Process {pid}\n\n"
        markdown_report += analyzer.tree_to_markdown(process_tree)
        
        # Add associated events (all types)
        if self.unified_df is not None:
            associated_events = self.unified_df[self.unified_df['process_id'] == pid]
            
            markdown_report += "\n\n## Associated Events\n"
            if len(associated_events) == 0:
                markdown_report += "\nNo associated events found.\n"
            else:
                for _, event in associated_events.iterrows():
                    markdown_report += f"\n- {event['event_type']} event at {event['event_time']}\n"
                    if event['event_type'] == 'network':
                        markdown_report += f"  - Source: {event.get('src_ip', 'N/A')}:{event.get('src_port', 'N/A')}\n"
                        markdown_report += f"  - Destination: {event.get('dst_ip', 'N/A')}:{event.get('dst_port', 'N/A')}\n"
                    elif event['event_type'] == 'file':
                        markdown_report += f"  - File: {event.get('file_path', 'N/A')}\n"
                        markdown_report += f"  - Operation: {event.get('operation', 'N/A')}\n"
                    elif event['event_type'] == 'registry':
                        markdown_report += f"  - Registry Key: {event.get('registry_key', 'N/A')}\n"
                        markdown_report += f"  - Operation: {event.get('operation', 'N/A')}\n"
                        if pd.notna(event.get('value_name')):
                            markdown_report += f"  - Value Name: {event.get('value_name', 'N/A')}\n"
                            markdown_report += f"  - Value Data: {event.get('value_data', 'N/A')}\n"
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        with open(f"reports/process_tree_{pid}.md", "w") as f:
            f.write(markdown_report)
        
        logger.info(f"Generated process tree report for PID {pid} in reports/process_tree_{pid}.md")
    
    def save_unified_data(self):
        """Save unified data to a CSV file."""
        if self.unified_df is not None:
            os.makedirs("data", exist_ok=True)
            self.unified_df.to_csv("data/unified_events.csv", index=False)
            logger.info("Saved unified data to data/unified_events.csv")

def main():
    """Main execution function."""
    import argparse
    parser = argparse.ArgumentParser(description='Security Event Analyzer')
    parser.add_argument('--data-dir', type=str, required=True,
                       help='Path to directory containing input CSV files')
    parser.add_argument('--pid', type=int, default=15150,
                       help='Process ID to analyze (default: 15150)')
    args = parser.parse_args()
    
    try:
        analyzer = SecurityEventAnalyzer(args.data_dir)
        
        # Step 1: Load data
        analyzer.load_data()
        
        # Step 2: Clean data
        analyzer.clean_data()
        
        # Step 3: Integrate data
        analyzer.integrate_data()
        analyzer.save_unified_data()
        
        # Step 4: Analyze malicious process
        analyzer.analyze_malicious_process(args.pid)
        
        logger.info("Analysis completed successfully")
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        raise

if __name__ == "__main__":
    main()