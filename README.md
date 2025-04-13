# Compete-Q-QS

A Python project for managing and analyzing QuickSight dashboards and reports using AWS services.

## Overview

This project provides tools and utilities for working with Amazon QuickSight dashboards and reports. It leverages AWS services through the boto3 library and includes functionality for managing QuickSight resources programmatically.

## Features

- QuickSight dashboard management
- AWS integration through boto3
- Environment-based configuration
- CLI interface through MCP

## Prerequisites

- Python 3.13 or higher
- AWS credentials configured
- QuickSight access permissions

## Installation

1. Clone the repository:
```bash
git clone [your-repository-url]
cd compete-q-qs
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -e .
```

## Configuration

1. Create a `.env` file in the project root with your AWS credentials:
```
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=your_region
```

## Usage

[Add specific usage instructions here based on your project's functionality]

## Dependencies

- boto3 >= 1.37.33
- python-dotenv >= 1.1.0
- mcp[cli] >= 1.2.0
- httpx >= 0.24.0

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]

## Support

[Add support information here]
