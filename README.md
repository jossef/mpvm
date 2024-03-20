# Checkmarx MPVM (Malicious Packages and Vulnerabilities Manager)

## Overview
This script is designed to scan code projects for supply chain risks and vulnerabilities by leveraging Checkmarx's Supply Chain Security (SCS) Threat Intelligence API. It supports multiple package types and can operate in both online and offline modes.

# Docker Image

To run mpvm, you can use this Docker image [`jossef/mpvm`](https://hub.docker.com/r/jossef/mpvm): 
```
docker run -v ./output/offline_results.json:/resolver.json -v ./output:/output jossef/mpvm:v1.0.0 --resolver-json /resolver.json -o /output -t {{Checkmarx Threat Intel API token}}
```

# Python Script
To run mpvm from source, use the following instructions:   

## Requirements
- Python 3.x
- `requests` library (can be installed via `pip install requests`)
- An active internet connection for online mode
- Checkmarx SCS Threat Intelligence API token for online mode

## Installation
1. Ensure Python 3.x is installed on your system.
2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```
3. Clone this repository or download the script to your local machine.

## Usage
To use the script, run it from the command line with the necessary arguments. Below is the basic usage syntax:

```
python main.py [OPTIONS]
```

### Options
- `-s`, `--source-dir`: Source project directory path to scan (required in certain modes).
- `-t`, `--token`: Checkmarx SCS Threat Intelligence API token (required).
- `-o`, `--output-dir`: Directory path for results output (optional).
- `-d`, `--dependencies`: Path to an external input of dependencies JSON file for quicker scans (optional).
- `-v`, `--verbose`: Enable verbose output (optional).
- `--resolver-json`: Path to Checkmarx dependency resolver raw JSON file (optional).
- `--offline`: Enable offline mode, which only produces dependency resolution (optional).
- `--upload`: Specify upload mode (optional).

### Examples
Scanning a project in online mode:
```
python main.py -s /path/to/source/dir -t YOUR_API_TOKEN
```

Running in offline mode for dependency resolution:
```
python main.py --offline -s /path/to/source/dir
```

## Output
The script generates several JSON files in the specified output directory (or a default one if not specified), containing detailed information about detected dependencies, vulnerabilities, and supply chain risks.

## Support
For issues, questions, or contributions, please open an issue in the GitHub repository where this script is hosted.

## Disclaimer
This script is provided "as is", without warranty of any kind. Use of this script is at your own risk.
