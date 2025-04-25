from setuptools import setup, find_packages

setup(
    name="cobra-scan",
    version="0.1",
    packages=find_packages(),
    install_requires=["click", "rich", "requests"],
    entry_points={
        "console_scripts": [
            "cobra=cobra.cli:cli",
        ],
    },
    author="Your Name",
    description="cobra - COBOL Risk Analyzer",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License"
    ],
    python_requires=">=3.10",
)
