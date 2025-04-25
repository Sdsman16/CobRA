from setuptools import setup, find_packages

setup(
    name="cobol-risk-analyzer",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "rich",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "cobra=cobra.cli:cli",
        ],
    },
    author="Sdsman16",
    author_email="your-email@example.com",
    description="CobRA: A COBOL Risk Analyzer for detecting vulnerabilities and providing fix recommendations.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Sdsman16/CobRA",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)