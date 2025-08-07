from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="droidsecanalytica",
    version="0.1.0",
    description="Menu-driven Android security analysis toolkit",
    packages=find_packages(),
    install_requires=requirements,
)
