from setuptools import find_packages, setup


install_requires = (
    "aiohttp==3.6.2",
    "yarl==1.5.1",
    "neuro_auth_client==19.10.5",
    "trafaret==2.0.2",
    "platform-logging==0.3",
    "aiohttp-cors==0.7.0",
)

setup(
    name="platform-secrets",
    version="0.0.1b1",
    url="https://github.com/neuromation/platform-secrets",
    packages=find_packages(),
    install_requires=install_requires,
    python_requires=">=3.7",
    entry_points={"console_scripts": ["platform-secrets=platform_secrets.api:main"]},
    zip_safe=False,
)
