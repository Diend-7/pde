from setuptools import setup, find_packages

setup(name='pde',
      version='0.1',
      description='A package can be used to access waveform data in the map system!',
      url='https://github.com/Diend-7/pde',
      author='WangPeiXian',
      author_email='2825642414@qq.com',
      license='MIT',
      packages=find_packages(),
      install_requires=["obspy"])