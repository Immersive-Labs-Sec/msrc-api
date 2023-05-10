# MSRC API Tool: Patch Tuesday Vulnerability Report Generator 

This Python script fetches and analyzes vulnerability data from Microsoft's Security Response Center (MSRC) API. It provides statistics on various types of vulnerabilities, including those that have been exploited and those that are more likely to be exploited.

## Improvements

The original codebase was refreshed with the following enhancements:

- **Error Handling**: Improved error handling was added. The script now catches potential exceptions that could occur during the HTTP request, providing more informative error messages for easier debugging.

- **Modularization**: The script was refactored for better modularization. The `__main__` section was broken down into several smaller functions, enhancing readability and reusability.

- **Input Validation**: The `check_data_format` function was enhanced to validate the date string more thoroughly, ensuring it not only matches a specific format, but is also a valid date.

- **Refactoring Repetitive Code**: Repetitive code patterns were refactored into their own functions, reducing code repetition and improving maintainability.

- **Code Formatting**: The code was revised to better adhere to the PEP 8 style guide, improving readability. This included changes such as adding spaces around operators and blank lines to separate functions.

- **Documentation**: Detailed comments and docstrings were added to explain the purpose and functionality of each part of the script. This includes what each function does, its inputs and outputs, and the overall functionality of the script.

## TODO

Further improvements can be made:

- **Code Comments**: While comments were added in some places, more detailed comments could be beneficial throughout the script.

## Usage

The script is intended to be run as a standalone Python program:

```bash
python patch_review.py <security_update>
```

Replace `<security_update>` with a date string in the format 'YYYY-mmm' representing the security update you want to fetch data for.

Example:

```bash
python patch_review.py 2023-Jan
```

## Requirements

This script requires the `requests` Python library to send the GET request to the MSRC API. You can install it with pip:

```bash
pip install requests
```

