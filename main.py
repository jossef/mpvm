import argparse
import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
import tarfile
import requests
from requests.adapters import HTTPAdapter, Retry

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
UTILS_DIR_PATH = os.path.join(SCRIPT_DIR, 'utils')

RESOLVER_FILE_NAME_WINDOWS = 'ScaResolver-win64.zip'
RESOLVER_FILE_NAME_LINUX = 'ScaResolver-linux64.tar.gz'
RESOLVER_FILE_NAME_MACOS = 'ScaResolver-macos64.tar.gz'

RESOLVER_URL_WINDOWS = 'https://sca-downloads.s3.amazonaws.com/cli/2.6.3/ScaResolver-win64.zip'
RESOLVER_URL_LINUX = 'https://sca-downloads.s3.amazonaws.com/cli/2.6.3/ScaResolver-linux64.tar.gz'
RESOLVER_URL_MACOS = 'https://sca-downloads.s3.amazonaws.com/cli/2.6.3/ScaResolver-macos64.tar.gz'
CHUNK_SIZE = 100

PACKAGE_TYPE_NPM = 'npm'
PACKAGE_TYPE_PYPI = 'pypi'
PACKAGE_TYPE_PUB = 'pub'
PACKAGE_TYPE_RUBYGEMS = 'rubygems'
PACKAGE_TYPE_MVN = 'mvn'
PACKAGE_TYPE_GO = 'go'
PACKAGE_TYPE_PACKAGIST = 'packagist'
PACKAGE_TYPE_NUGET = 'nuget'
PACKAGE_TYPE_SWIFT = 'swift'
PACKAGE_TYPE_CARGO = 'cargo'
PACKAGE_TYPE_GROOVY = 'groovy'
PACKAGE_TYPE_SCALA = 'scala'
PACKAGE_TYPE_KOTLIN = 'kotlin'
PACKAGE_TYPE_COCOAPODS = 'cocoapods'
PACKAGE_TYPE_CONAN = 'conan'
PACKAGE_TYPE_CONDA = 'conda'

CASE_SENSITIVE_TYPES = {PACKAGE_TYPE_MVN, PACKAGE_TYPE_RUBYGEMS, PACKAGE_TYPE_PUB, PACKAGE_TYPE_GROOVY, PACKAGE_TYPE_SCALA, PACKAGE_TYPE_KOTLIN}


def download_resolver_executable(temp_dir_path: str):
    if sys.platform == 'win32':
        resolver_archive_file_name = RESOLVER_FILE_NAME_WINDOWS
        resolver_url = RESOLVER_URL_WINDOWS
    elif sys.platform == 'linux':
        resolver_archive_file_name = RESOLVER_FILE_NAME_LINUX
        resolver_url = RESOLVER_URL_LINUX
    elif sys.platform == 'darwin':
        resolver_archive_file_name = RESOLVER_FILE_NAME_MACOS
        resolver_url = RESOLVER_URL_MACOS
    else:
        raise Exception(f'unsupported platform: {sys.platform}')

    local_resolver_archive_file_path = os.path.join(UTILS_DIR_PATH, resolver_archive_file_name)
    temp_resolver_archive_file_path = os.path.join(temp_dir_path, resolver_archive_file_name)

    if os.path.isfile(local_resolver_archive_file_path):
        logging.debug(f'copying resolver from "{local_resolver_archive_file_path}" to "{temp_resolver_archive_file_path}"')
        shutil.copy2(local_resolver_archive_file_path, temp_resolver_archive_file_path)
    else:
        logging.info(f'downloading resolver from {resolver_url}')
        r = requests.get(resolver_url, allow_redirects=True)
        r.raise_for_status()
        with open(temp_resolver_archive_file_path, 'wb') as f:
            f.write(r.content)

    # -------------
    # Extract archive
    logging.debug(f'extracting resolver archive')

    if temp_resolver_archive_file_path.endswith('.zip'):
        with zipfile.ZipFile(temp_resolver_archive_file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir_path)
    else:
        with tarfile.open(temp_resolver_archive_file_path, 'r:gz' if sys.platform == 'linux' else 'r') as tar_ref:
            tar_ref.extractall(temp_dir_path)

    resolver_exe_file_path = os.path.join(temp_dir_path, 'ScaResolver.exe' if sys.platform == 'win32' else 'ScaResolver')
    logging.debug(f'extracted resolver to {resolver_exe_file_path}')

    return resolver_exe_file_path


def normalize_package_type(package_type) -> str:
    package_type = package_type.lower()

    if package_type == 'java':
        package_type = PACKAGE_TYPE_MVN
    elif package_type == 'maven':
        package_type = PACKAGE_TYPE_MVN
    elif package_type == 'nuget':
        package_type = PACKAGE_TYPE_NUGET
    elif package_type == 'cocoapods':
        package_type = PACKAGE_TYPE_COCOAPODS
    elif package_type == 'conan':
        package_type = PACKAGE_TYPE_CONAN
    elif package_type == 'conda':
        package_type = PACKAGE_TYPE_CONDA
    elif package_type == 'yarn':
        package_type = PACKAGE_TYPE_NPM
    elif package_type == 'ruby':
        package_type = PACKAGE_TYPE_RUBYGEMS
    elif package_type == 'ios':
        package_type = PACKAGE_TYPE_SWIFT
    elif package_type == 'composer':
        package_type = PACKAGE_TYPE_PACKAGIST
    elif package_type == 'php':
        package_type = PACKAGE_TYPE_PACKAGIST
    elif package_type == 'pip':
        package_type = PACKAGE_TYPE_PYPI
    elif package_type == 'swiftpm':
        package_type = PACKAGE_TYPE_SWIFT
    elif package_type == 'gradle':
        package_type = PACKAGE_TYPE_MVN
    elif package_type == 'ivy':
        package_type = PACKAGE_TYPE_MVN
    elif package_type == 'bower':
        package_type = PACKAGE_TYPE_NPM
    elif package_type == 'carthage':
        package_type = PACKAGE_TYPE_SWIFT
    elif package_type == 'cocoapods':
        package_type = PACKAGE_TYPE_SWIFT
    elif package_type == 'gomodules':
        package_type = PACKAGE_TYPE_GO
    elif package_type == 'sbt':
        package_type = PACKAGE_TYPE_MVN
    elif package_type == 'rubygems':
        package_type = PACKAGE_TYPE_RUBYGEMS
    elif package_type == 'poetry':
        package_type = PACKAGE_TYPE_PYPI
    elif package_type == 'dart':
        package_type = PACKAGE_TYPE_PUB
    elif package_type == 'pub':
        package_type = PACKAGE_TYPE_PUB
    elif package_type == 'npm':
        package_type = PACKAGE_TYPE_NPM
    elif package_type == 'pypi':
        package_type = PACKAGE_TYPE_PYPI
    else:
        return ''

    return package_type


def normalize_package_name(package_name: str, package_type: str) -> str:
    package_type = package_type.lower()

    if package_type not in CASE_SENSITIVE_TYPES:
        package_name = package_name.lower()

    if package_type == PACKAGE_TYPE_GO or package_type == PACKAGE_TYPE_SWIFT:
        temp_package_name = package_name.split('://')[-1]
        parts = temp_package_name.split('/')
        if len(parts) >= 3:
            site = parts[0]
            repo_username = parts[1]
            repo_name = parts[2]
            package_name = f'{site}/{repo_username}/{repo_name}'

    return package_name


def split_chunks(items: list, chunk_size: int):
    chunks = []
    for i in range(0, len(items), chunk_size):
        chunk = items[i: i + chunk_size]
        chunks.append(chunk)

    return chunks


def main():
    parser = argparse.ArgumentParser(description='CLI to scan a code project for supply chain risks and vulnerabilities')
    parser.add_argument('-s', '--source-dir', dest='source_dir_path', help='Source project directory path to scan', required='--offline' in sys.argv and '--resolver-json' not in sys.argv)
    parser.add_argument('-t', '--token', dest='scs_api_token', help='Checkmarx SCS Threat Intelligence API token', required=True)
    parser.add_argument('-o', '--output-dir', dest='output_dir_path', help='results output dir path', required=False)
    parser.add_argument('-d', '--dependencies', dest='dependencies_file_path', help='external input of dependencies json file for quicker scans', required='--upload' in sys.argv)
    parser.add_argument('-v', '--verbose', dest='verbose', help='verbose output', action='store_true', default=False, required=False)
    parser.add_argument('--resolver-json', dest='resolver_raw_json_file_path', help='checkmarx dependency resolver raw json file path', required=False)
    parser.add_argument('--offline', dest='offline', help='offline mode, only produces dependency resolution', action='store_true', default=False, required=False)
    parser.add_argument('--upload', dest='upload', help='offline mode, only produces dependency resolution', action='store_true', default=False, required=False)
    args = parser.parse_args()

    source_dir_path = args.source_dir_path
    scs_api_token = args.scs_api_token
    output_dir_path = args.output_dir_path

    dependencies_file_path = args.dependencies_file_path
    resolver_raw_json_file_path = args.resolver_raw_json_file_path
    verbose = args.verbose
    offline = args.offline

    if offline:
        logging.info('offline mode enabled')

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # -------------

    if not output_dir_path:
        output_dir_path = os.path.join(os.getcwd(), f'checkmarx_scan_results_{datetime.datetime.now().isoformat().split(".")[0].replace(":", "-")}')

    if not os.path.isdir(output_dir_path):
        logging.debug(f"creating output directory {output_dir_path}")
        os.makedirs(output_dir_path, exist_ok=True)

    # -------------
    # Resolve Dependencies

    if dependencies_file_path:
        with open(dependencies_file_path, 'r') as f:
            packages = json.load(f)
    else:
        if resolver_raw_json_file_path:
            logging.info(f"reading resolver results from {resolver_raw_json_file_path}")
            with open(resolver_raw_json_file_path, 'r') as f:
                resolver_results = json.load(f)
        else:
            logging.info("deploying dependency resolver")
            with tempfile.TemporaryDirectory() as temp_dir_path:
                resolver_results_file_path = os.path.join(temp_dir_path, 'resolver_results.json')
                resolver_exe_file_path = download_resolver_executable(temp_dir_path)
                logging.info(f'resolving dependencies ... (may take several minutes)')
                process = subprocess.Popen([resolver_exe_file_path, 'offline', '-s', source_dir_path, '-n', 'CLI_LOCAL_RESOLVER', '-r', resolver_results_file_path], cwd=temp_dir_path, stdout=None if verbose else subprocess.DEVNULL, stderr=None if verbose else subprocess.DEVNULL)
                process.wait()
                if process.returncode != 0:
                    raise Exception(f'dependencies resolver failed with unexpected error. exit code {process.returncode}')

                with open(resolver_results_file_path, 'r') as f:
                    resolver_results = json.load(f)

        # -------------
        # Normalize Resolver Dependencies

        dependencies = []
        for resolution_result in resolver_results.get('DependencyResolutionResults', []):
            package_type = resolution_result['ResolvingModuleType']
            for dependency in resolution_result.get('Dependencies', []):
                package_name = dependency['Id']['Name']
                package_version = dependency['Id']['Version']

                dependencies.append(
                    {
                        "name": package_name,
                        "version": package_version,
                        "type": package_type
                    }
                )

                for child_dependency in dependency.get('Children', []):
                    child_package_name = child_dependency['Name']
                    child_package_version = child_dependency['Version']

                    dependencies.append(
                        {
                            "name": child_package_name,
                            "version": child_package_version,
                            "type": package_type
                        }
                    )

        packages = {}
        for dependency in dependencies:
            package_name = dependency['name']
            package_type = dependency['type']
            package_type = normalize_package_type(package_type)
            if not package_type:
                logging.warning(f'unsupported package type "{package_type}" for package "{package_name}"')
                continue

            package_name = normalize_package_name(package_name, package_type)
            package_version = dependency['version']
            package_id = f"{package_type}/{package_name}/{package_version}"
            packages[package_id] = {
                "name": package_name,
                "version": package_version,
                "type": package_type
            }

    dependencies_output_file_path = os.path.join(output_dir_path, 'dependencies.json')
    logging.info(f'saving dependencies to "{dependencies_output_file_path}"')
    with open(dependencies_output_file_path, 'w+') as f:
        json.dump(packages, f, indent=2)

    if offline:
        logging.debug('offline mode enabled. stopping')
        return

    # -------------
    # Query SCS API

    packages = packages.values()
    packages = list(packages)
    chunks = split_chunks(packages, CHUNK_SIZE)

    vulnerabilities = []
    supply_chain_risks = []

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    logging.info(f'querying Checkmarx Supply Chain Security Threat Intelligence API for total of {len(packages)} packages (in {len(chunks)} chunks)')
    for chunk_id, chunk in enumerate(chunks):
        logging.info(f'query {chunk_id + 1}/{len(chunks)}')
        r = session.post('https://api.scs.checkmarx.com/v1/packages/vulnerabilities', headers={'Authorization': scs_api_token}, json=chunk, timeout=30)
        r.raise_for_status()
        chunk_vulnerabilities = r.json()
        chunk_vulnerabilities = filter(lambda x: x.get('vulnerabilities', []), chunk_vulnerabilities)
        chunk_vulnerabilities = list(chunk_vulnerabilities)
        vulnerabilities.extend(chunk_vulnerabilities)

        r = session.post('https://api.scs.checkmarx.com/v1/packages', headers={'Authorization': scs_api_token}, json=chunk, timeout=30)
        r.raise_for_status()
        chunk_supply_chain_risks = r.json()
        chunk_supply_chain_risks = filter(lambda x: x.get('risks', []), chunk_supply_chain_risks)
        chunk_supply_chain_risks = list(chunk_supply_chain_risks)
        supply_chain_risks.extend(chunk_supply_chain_risks)

    # -------------
    # Saving results

    sca_results_file_path = os.path.join(output_dir_path, 'sca-results.json')
    logging.info(f'saving sca results to "{sca_results_file_path}"')
    with open(sca_results_file_path, 'w+') as f:
        json.dump(vulnerabilities, f, indent=2)

    scs_results_file_path = os.path.join(output_dir_path, 'scs-results.json')
    logging.info(f'saving scs results to "{sca_results_file_path}"')
    with open(scs_results_file_path, 'w+') as f:
        json.dump(supply_chain_risks, f, indent=2)

    # -------------
    # Summary

    total_packages = len(packages)
    total_supply_chain_risks = 0
    for item in supply_chain_risks:
        total_supply_chain_risks += len(item.get('risks', []))

    total_vulnerable_packages = 0
    total_vulnerabilities = 0
    total_critical_vulnerabilities = 0
    total_high_vulnerabilities = 0
    total_medium_vulnerabilities = 0
    total_low_vulnerabilities = 0
    for item in vulnerabilities:
        item_vulnerabilities = item.get('vulnerabilities', [])
        total_vulnerabilities += len(item_vulnerabilities)
        if item_vulnerabilities:
            total_vulnerable_packages += 1

        for item_vulnerability in item_vulnerabilities:
            item_vulnerability_severity = item_vulnerability.get('severity', '')
            item_vulnerability_severity = item_vulnerability_severity.lower()
            if item_vulnerability_severity == 'critical':
                total_critical_vulnerabilities += 1

            elif item_vulnerability_severity == 'high':
                total_high_vulnerabilities += 1

            elif item_vulnerability_severity == 'medium':
                total_medium_vulnerabilities += 1

            elif item_vulnerability_severity == 'low':
                total_low_vulnerabilities += 1

    output = f'''---------------------------------- Checkmarx Scan Results ---------------------------------- 
Detected Packages: {total_packages}
Supply Chain Risks: {total_supply_chain_risks}
Detected Vulnerable Packages: {total_vulnerable_packages}
Vulnerabilities: {total_vulnerabilities}
\t- Critical: {total_critical_vulnerabilities}
\t- High: {total_high_vulnerabilities}
\t- Medium: {total_medium_vulnerabilities}
\t- Low: {total_low_vulnerabilities}

Scan results dir path: {output_dir_path}
    '''

    scan_summary_file_path = os.path.join(output_dir_path, 'summary.json')
    logging.info(f'saving scan summary to "{scan_summary_file_path}"')
    with open(scan_summary_file_path, 'w+') as f:
        json.dump({
            "timestamp": datetime.datetime.now().isoformat(),
            "total_packages": total_packages,
            "total_supply_chain_risks": total_supply_chain_risks,
            "total_vulnerable_packages": total_vulnerable_packages,
            "total_vulnerabilities": total_vulnerabilities,
            "total_critical_vulnerabilities": total_critical_vulnerabilities,
            "total_high_vulnerabilities": total_high_vulnerabilities,
            "total_medium_vulnerabilities": total_medium_vulnerabilities,
            "total_low_vulnerabilities": total_low_vulnerabilities,
        }, f, indent=2)

    logging.info(output)


if __name__ == '__main__':
    try:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
        logging.debug(f'starting "{" ".join(sys.argv)}"')
        main()
        logging.info('finished successfully')
    except (SystemExit, KeyboardInterrupt):
        pass
    except:
        logging.exception('unexpected error')
        sys.exit(1)
