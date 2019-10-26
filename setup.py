import re

import setuptools

with open("./oidckit/__init__.py", "r") as infp:
    version = re.search("__version__ = ['\"]([^'\"]+)['\"]", infp.read()).group(1)

dev_dependencies = ["flake8", "isort", "pydocstyle", "pytest-cov", "pytest"]

if __name__ == "__main__":
    setuptools.setup(
        name="oidckit",
        description="Unobtrusive pluggable OpenID Connect",
        version=version,
        url="https://github.com/valohai/oidckit",
        author="Valohai",
        maintainer="Aarni Koskela",
        maintainer_email="akx@iki.fi",
        license="MIT",
        install_requires=["requests", "josepy>=1.2.0"],
        tests_require=dev_dependencies,
        extras_require={"dev": dev_dependencies},
        packages=setuptools.find_packages(".", exclude=("*tests",)),
        include_package_data=True,
        python_requires=">=3.6",
    )
