# CVE Lookup Web Application

The CVE Lookup web application is a tool that allows users to search for information about Common Vulnerabilities and Exposures (CVE) IDs. It retrieves data from the National Vulnerability Database (NVD) and Vulmon, presenting it in an easily accessible format for users.

![Screenshot](screenshot.png)

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Features

- **CVE ID Lookup**: Users can enter a CVE ID (e.g., CVE-2021-12345) to retrieve detailed information.
- **Data Sources**: The application fetches CVE descriptions and severity from both NVD and Vulmon.
- **User-Friendly Interface**: A clean and intuitive interface ensures easy navigation and error handling for invalid CVE IDs.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- **Python**: Ensure you have Python 3.x installed.
- **Required Packages**: Install necessary Python packages using the `requirements.txt` file.

   ```bash
   pip install -r requirements.txt
