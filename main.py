import argparse
import difflib
import json
import logging
import os
import subprocess
import sys
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigDiffAnomalyDetector:
    """
    Analyzes configuration diffs and flags anomalies.
    """

    def __init__(self, config_dir, threshold=0.1, file_types=['yaml', 'json']):  # Add file_types
        """
        Initializes the ConfigDiffAnomalyDetector.

        Args:
            config_dir (str): The directory containing configuration files.
            threshold (float): The anomaly detection threshold (default: 0.1).
            file_types (list): List of file types to analyze (default: ['yaml', 'json']).
        """
        self.config_dir = config_dir
        self.threshold = threshold
        self.file_types = file_types
        self.config_history = {}

    def load_config_history(self):
        """
        Loads configuration history from the specified directory.
        """
        logging.info("Loading configuration history...")
        for filename in os.listdir(self.config_dir):
            if any(filename.endswith(ext) for ext in self.file_types):
                filepath = os.path.join(self.config_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        self.config_history[filename] = [content]  # Initialize with the current content

                except Exception as e:
                    logging.error(f"Error loading config file {filename}: {e}")

    def get_latest_config(self, filename):
      """
      Returns the latest configuration content for a given file.

      Args:
          filename (str): The name of the configuration file.

      Returns:
          str: The latest configuration content, or None if not found.
      """
      if filename in self.config_history and self.config_history[filename]:
        return self.config_history[filename][-1]
      else:
        return None


    def analyze_diff(self, filename, new_content):
        """
        Analyzes the diff between the current and previous versions of a config file.

        Args:
            filename (str): The name of the configuration file.
            new_content (str): The new content of the configuration file.

        Returns:
            bool: True if an anomaly is detected, False otherwise.
        """
        latest_content = self.get_latest_config(filename)

        if not latest_content:
            logging.info(f"First time seeing config file: {filename}")
            self.config_history[filename] = [new_content]
            return False  # Not an anomaly as it's the first version


        diff = difflib.unified_diff(latest_content.splitlines(), new_content.splitlines(), fromfile="old", tofile="new")
        diff_lines = list(diff)
        diff_ratio = len(diff_lines) / (len(latest_content.splitlines()) + len(new_content.splitlines()) + 1e-9) #Avoid zero division

        logging.debug(f"Diff ratio for {filename}: {diff_ratio}")

        if diff_ratio > self.threshold:
            logging.warning(f"Anomaly detected in {filename}. Diff ratio: {diff_ratio}")
            return True
        else:
            logging.info(f"No anomaly detected in {filename}. Diff ratio: {diff_ratio}")
            return False

    def update_config_history(self, filename, new_content):
        """
        Updates the configuration history with the new content.

        Args:
            filename (str): The name of the configuration file.
            new_content (str): The new content of the configuration file.
        """
        if filename in self.config_history:
            self.config_history[filename].append(new_content)
        else:
            self.config_history[filename] = [new_content] #Handle first time the file is encountered


    def run_linters(self, filename, filepath):
        """
        Runs linters (yamllint, jsonlint) based on the file extension.

        Args:
            filename (str): The name of the configuration file.
            filepath (str): The full path to the configuration file.

        Returns:
            bool: True if linting passes, False otherwise.
        """
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            try:
                result = subprocess.run(["yamllint", filepath], capture_output=True, text=True)
                if result.returncode != 0:
                    logging.error(f"yamllint failed for {filename}: {result.stderr}")
                    return False
                else:
                    logging.info(f"yamllint passed for {filename}")
                    return True
            except FileNotFoundError:
                logging.error("yamllint not found. Please ensure it is installed.")
                return False
        elif filename.endswith(".json"):
            try:
                result = subprocess.run(["jsonlint", "-q", filepath], capture_output=True, text=True)
                if result.returncode != 0:
                    logging.error(f"jsonlint failed for {filename}: {result.stderr}")
                    return False
                else:
                    logging.info(f"jsonlint passed for {filename}")
                    return True
            except FileNotFoundError:
                logging.error("jsonlint not found. Please ensure it is installed.")
                return False
        else:
            logging.warning(f"No linter configured for file type: {filename}")
            return True  # Consider it passing, or implement generic linting

    def scan_directory(self):
        """
        Scans the configuration directory for changes and anomalies.
        """
        logging.info("Scanning configuration directory...")
        anomalies_found = False
        for filename in os.listdir(self.config_dir):
            if any(filename.endswith(ext) for ext in self.file_types):
                filepath = os.path.join(self.config_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        new_content = f.read()

                    if not self.run_linters(filename, filepath):
                        logging.warning(f"Linting failed for {filename}. Skipping anomaly detection.")
                        continue

                    if self.analyze_diff(filename, new_content):
                        anomalies_found = True

                    self.update_config_history(filename, new_content)


                except Exception as e:
                    logging.error(f"Error processing {filename}: {e}")
        
        if anomalies_found:
            logging.warning("Anomalies were detected in the configuration files.")
        else:
            logging.info("No anomalies were detected.")
        
        return not anomalies_found  # Return True if no anomalies found, False otherwise.


def setup_argparse():
    """
    Sets up the argument parser for the command line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Detects anomalies in configuration file changes.")
    parser.add_argument("config_dir", help="The directory containing configuration files.")
    parser.add_argument("-t", "--threshold", type=float, default=0.1, help="The anomaly detection threshold (default: 0.1).")
    parser.add_argument("-f", "--file_types", nargs="+", default=['yaml', 'json'], help="List of file types to analyze (default: yaml json).")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging.")

    return parser

def main():
    """
    Main function to execute the ConfigDiffAnomalyDetector.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug logging enabled.")

    # Validate config_dir
    if not os.path.isdir(args.config_dir):
        logging.error(f"Error: '{args.config_dir}' is not a valid directory.")
        sys.exit(1)

    # Validate threshold
    if not 0 <= args.threshold <= 1:
        logging.error("Error: Threshold must be between 0 and 1.")
        sys.exit(1)

    # Validate file_types
    for file_type in args.file_types:
      if not isinstance(file_type, str):
        logging.error("File types must be string values.")
        sys.exit(1)

    try:
        detector = ConfigDiffAnomalyDetector(args.config_dir, args.threshold, args.file_types)
        detector.load_config_history()
        success = detector.scan_directory()

        if success:
          sys.exit(0) # exit with success code
        else:
          sys.exit(1) # exit with failure code
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()