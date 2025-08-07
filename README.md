# DroidSecAnalytica

DroidSecAnalytica is a menu-driven toolkit for performing static and analytical
security checks on Android applications. It combines APK decompilation,
permission inspection, VirusTotal lookups and reporting utilities backed by a
MySQL database.

## Prerequisites

- Python 3.8 or later
- [pip](https://pip.pypa.io/) for installing Python packages
- A MySQL server with credentials configured in `database/db_config.py`
- [`apktool`](https://ibotpeaches.github.io/Apktool/) available on the system `PATH`

## Installation

Clone the repository and install the required Python packages (versions pinned in
`requirements.txt` for reproducibility):

```bash
pip install -r requirements.txt
```

Alternatively run the provided setup helper which installs dependencies and
verifies database connectivity:

```bash
python scripts/setup.py
```

To skip installing dependencies or database checks, pass `--skip-install` or
`--skip-db-check` respectively.

## Usage

Launch the interactive menu from the project root:

```bash
python main.py
```

Modules for static analysis, VirusTotal queries, and report generation are
accessible from this menu.

## Development

A `setup.py` script is included to support standard `pip install .` workflows
and resolves dependencies from `requirements.txt`.

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
