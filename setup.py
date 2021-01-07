from setuptools import find_packages, setup


setup_requires = ("setuptools_scm",)

install_requires = (
    "aiohttp==3.7.3",
    "yarl==1.6.2",
    "multidict==5.1.0",
    "neuro_auth_client==21.1.6",
    "trafaret==2.1.0",
    "platform-logging==0.3",
    "aiohttp-cors==0.7.0",
)

setup(
    name="platform-secrets",
    url="https://github.com/neuromation/platform-secrets",
    use_scm_version={
        "git_describe_command": "git describe --dirty --tags --long --match v*.*.*",
    },
    packages=find_packages(),
    setup_requires=setup_requires,
    install_requires=install_requires,
    python_requires=">=3.7",
    entry_points={"console_scripts": ["platform-secrets=platform_secrets.api:main"]},
    zip_safe=False,
)
