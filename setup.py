from setuptools import find_packages, setup


setup_requires = ("setuptools_scm",)

install_requires = (
    "aiohttp==3.7.4.post0",
    "yarl==1.6.3",
    "multidict==5.1.0",
    "neuro_auth_client==21.6.15",
    "trafaret==2.1.0",
    "platform-logging==21.5.27",
    "aiohttp-cors==0.7.0",
    "aiozipkin==1.1.0",
    "sentry-sdk==1.2.0",
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
    python_requires=">=3.8",
    entry_points={"console_scripts": ["platform-secrets=platform_secrets.api:main"]},
    zip_safe=False,
)
